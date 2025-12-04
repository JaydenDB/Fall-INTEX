require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const knexLib = require("knex");

const app = express();

/* --------------------------------------------------
   VIEW ENGINE
-------------------------------------------------- */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* --------------------------------------------------
   STATIC FILES + UPLOADS
-------------------------------------------------- */
const uploadRoot = path.join(__dirname, "images");
const uploadDir = path.join(uploadRoot, "uploads");

// Make sure upload directory exists
if (!fs.existsSync(uploadRoot)) fs.mkdirSync(uploadRoot);
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

const upload = multer({ storage });

app.use("/images", express.static(uploadRoot));
app.use(
  "/images/rotate-images",
  express.static(path.join(__dirname, "public", "images", "rotate-images"))
);
app.use(express.static("public"));

/* --------------------------------------------------
   SESSION
-------------------------------------------------- */
app.use(
  session({
    secret: process.env.SESSION_SECRET || "fallback-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

/* --------------------------------------------------
   CONSTANTS (DONOR LEVELS)
-------------------------------------------------- */
const DONOR_LEVEL_PLATINUM = process.env.DONOR_LEVEL_PLATINUM
  ? Number(process.env.DONOR_LEVEL_PLATINUM)
  : 2000;
const DONOR_LEVEL_GOLD = process.env.DONOR_LEVEL_GOLD
  ? Number(process.env.DONOR_LEVEL_GOLD)
  : 1000;
const DONOR_LEVEL_SILVER = process.env.DONOR_LEVEL_SILVER
  ? Number(process.env.DONOR_LEVEL_SILVER)
  : 500;

/* --------------------------------------------------
   BODY PARSING
-------------------------------------------------- */
app.use(express.urlencoded({ extended: true }));

/* --------------------------------------------------
   DATABASE (Postgres intex)
-------------------------------------------------- */
const knex = knexLib({
  client: "pg",
  connection: {
    host: "intexdb.c70cumo8kg8k.us-east-2.rds.amazonaws.com",
    user: "postgres",
    password: "intexpassword",
    database: "intexdb",
    port: 5432,
    ssl: { rejectUnauthorized: false },
  },
  searchPath: ["ellarises"],
});

// quick connection test
knex
  .raw("SELECT 1")
  .then(() => console.log("✅ Connected to PostgreSQL (intex)"))
  .catch((err) => console.error("❌ DB connection error:", err.message));

/* --------------------------------------------------
   AUTH HELPERS
-------------------------------------------------- */
function attachUser(req, res, next) {
  res.locals.user = req.session.user || null;
  next();
}
app.use(attachUser);

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access denied. Admins only.");
  }
  next();
}

function pct(part, whole) {
  if (!whole || whole === 0) return "—";
  return Math.round((part / whole) * 100) + "%";
}

/* --------------------------------------------------
   ID HELPERS (WORKAROUND BROKEN SEQUENCES)
-------------------------------------------------- */

async function getNextParticipantId() {
  const row = await knex("participants").max("participantid as maxId").first();
  const maxId = Number(row?.maxId || 0);
  return maxId + 1;
}

async function getNextEventTemplateId() {
  const row = await knex("eventtemplates")
    .max("eventtemplateid as maxId")
    .first();
  const maxId = Number(row?.maxId || 0);
  return maxId + 1;
}

/* --------------------------------------------------
   STATS HELPERS
-------------------------------------------------- */

async function buildParticipantStats(participantId, participantEmail) {
  const emailLower = participantEmail ? participantEmail.toLowerCase() : null;

  const donationsWhere = (qb) => {
    if (participantId) qb.where("participantid", participantId);
    if (emailLower) qb.orWhereRaw("LOWER(participantemail) = ?", [emailLower]);
  };

  const emailWhere = (qb) => {
    if (emailLower) qb.whereRaw("LOWER(participantemail) = ?", [emailLower]);
    else qb.whereRaw("1 = 0");
  };

  const [
    donationAgg,
    recentDonations,
    surveyAgg,
    recentSurveys,
    milestones,
    regTotalRow,
    regAttendedRow,
  ] = await Promise.all([
    knex("donations")
      .modify(donationsWhere)
      .sum("donationamount as totalamount")
      .count("donationid as donationcount")
      .min("donationdate as firstdonation")
      .max("donationdate as lastdonation")
      .first(),

    knex("donations")
      .modify(donationsWhere)
      .orderBy("donationdate", "desc")
      .limit(5)
      .select("donationdate", "donationamount"),

    knex("surveys")
      .modify(emailWhere)
      .count("surveyid as totalsurveys")
      .avg("surveysatisfactionscore as avgsatisfaction")
      .avg("surveyusefulnessscore as avgusefulness")
      .avg("surveyrecommendationscore as avgrecommend")
      .avg("surveyoverallscore as avgoverall")
      .first(),

    knex("surveys")
      .modify(emailWhere)
      .orderBy("surveysubmissiondate", "desc")
      .limit(5)
      .select(
        "eventname",
        "eventdatetimestart",
        "surveysubmissiondate",
        "surveysatisfactionscore",
        "surveyoverallscore"
      ),

    knex("milestones")
      .modify((qb) => {
        if (participantId) qb.where("participantid", participantId);
        if (emailLower) qb.orWhereRaw("LOWER(participantemail) = ?", [emailLower]);
      })
      .orderBy("milestonedate", "desc")
      .limit(10),

    knex("registrations")
      .modify((qb) => {
        if (participantId) qb.where("participantid", participantId);
        else if (emailLower) qb.whereRaw("LOWER(participantemail) = ?", [emailLower]);
        else qb.whereRaw("1 = 0");
      })
      .count("registrationid as totalregistrations")
      .first(),

    knex("registrations")
      .modify((qb) => {
        if (participantId) qb.where("participantid", participantId);
        else if (emailLower) qb.whereRaw("LOWER(participantemail) = ?", [emailLower]);
        else qb.whereRaw("1 = 0");
      })
      .where("registrationattendedflag", true)
      .count("registrationid as totalattended")
      .first(),
  ]);

  const totalRegistrations = Number(regTotalRow?.totalregistrations || 0);
  const totalAttended = Number(regAttendedRow?.totalattended || 0);

  return {
    donations: {
      totalAmount: Number(donationAgg?.totalamount || 0),
      donationCount: Number(donationAgg?.donationcount || 0),
      firstDonation: donationAgg?.firstdonation || null,
      lastDonation: donationAgg?.lastdonation || null,
      recent: recentDonations || [],
    },
    surveys: {
      totalSurveys: Number(surveyAgg?.totalsurveys || 0),
      avgSatisfaction: Number(surveyAgg?.avgsatisfaction || 0).toFixed(2),
      avgUsefulness: Number(surveyAgg?.avgusefulness || 0).toFixed(2),
      avgRecommend: Number(surveyAgg?.avgrecommend || 0).toFixed(2),
      avgOverall: Number(surveyAgg?.avgoverall || 0).toFixed(2),
      recent: recentSurveys || [],
    },
    milestones: milestones || [],
    registrations: {
      totalRegistrations,
      totalAttended,
      attendanceRate: pct(totalAttended, totalRegistrations),
    },
  };
}

async function buildEventStats(eventTemplateId) {
  const occurrences = await knex("eventoccurrences")
    .where("eventtemplateid", eventTemplateId)
    .orderBy("eventdatetimestart", "desc");

  const occIds = occurrences.map((o) => o.eventoccurrenceid);

  let totalRegistrations = 0;
  let totalAttended = 0;
  let totalSurveys = 0;
  let avgSatisfaction = 0;
  let avgOverall = 0;

  if (occIds.length > 0) {
    const [regTotalRow, regAttendedRow, surveyAggRow] = await Promise.all([
      knex("registrations")
        .whereIn("eventoccurrenceid", occIds)
        .count("registrationid as totalregistrations")
        .first(),
      knex("registrations")
        .whereIn("eventoccurrenceid", occIds)
        .where("registrationattendedflag", true)
        .count("registrationid as totalattended")
        .first(),
      knex("surveys as s")
        .join("registrations as r", "s.registrationid", "r.registrationid")
        .whereIn("r.eventoccurrenceid", occIds)
        .count("s.surveyid as totalsurveys")
        .avg("s.surveysatisfactionscore as avgsatisfaction")
        .avg("s.surveyoverallscore as avgoverall")
        .first(),
    ]);

    totalRegistrations = Number(regTotalRow?.totalregistrations || 0);
    totalAttended = Number(regAttendedRow?.totalattended || 0);
    totalSurveys = Number(surveyAggRow?.totalsurveys || 0);
    avgSatisfaction = Number(surveyAggRow?.avgsatisfaction || 0);
    avgOverall = Number(surveyAggRow?.avgoverall || 0);
  }

  return {
    occurrences,
    registrations: {
      totalRegistrations,
      totalAttended,
      attendanceRate: pct(totalAttended, totalRegistrations),
    },
    surveys: {
      totalSurveys,
      avgSatisfaction: totalSurveys > 0 ? avgSatisfaction.toFixed(2) : "0.00",
      avgOverall: totalSurveys > 0 ? avgOverall.toFixed(2) : "0.00",
    },
  };
}

/* --------------------------------------------------
   ROUTES
-------------------------------------------------- */

/* ----- API: carousel images ----- */
app.get("/api/carousel-images", (req, res) => {
  const carouselDir = path.join(__dirname, "public", "images", "rotate-images");

  try {
    const files = fs.readdirSync(carouselDir);
    const imageExtensions = [".jpg", ".jpeg", ".png", ".gif", ".webp"];
    const images = files
      .filter((file) =>
        imageExtensions.includes(path.extname(file).toLowerCase())
      )
      .map((file) => `/images/rotate-images/${file}`);

    res.json({ images });
  } catch (err) {
    console.error("Error reading carousel images:", err);
    res.json({ images: [] });
  }
});

/* ----- HOME / LANDING PAGE ----- */
app.get("/", async (req, res) => {
  const user = req.session.user || null;

  try {
    const [
      participantsCountRow,
      eventsCountRow,
      milestonesCountRow,
      participantsWithMilestoneRow,
      steamDegreeRow,
      steamJobRow,
      upcomingEventsRows,
      donorsAgg,
    ] = await Promise.all([
      knex("participants").count("participantid as count").first(),
      knex("eventoccurrences").count("eventoccurrenceid as count").first(),
      knex("milestones").count("milestoneid as count").first(),
      knex("milestones").countDistinct("participantid as count").first(),
      knex("milestones")
        .where(function () {
          this.whereRaw(
            "LOWER(milestonetitle) LIKE ANY (ARRAY[?, ?, ?, ?, ?, ?, ?, ?, ?])",
            [
              "%bs in%",
              "%ms in%",
              "%bachelor%",
              "%associate%",
              "%engineering%",
              "%computer science%",
              "%data science%",
              "%information systems%",
              "%drafting%",
            ]
          );
        })
        .countDistinct("participantid as count")
        .first(),
      knex("milestones")
        .where(function () {
          this.whereRaw(
            "LOWER(milestonetitle) LIKE ANY (ARRAY[?, ?, ?, ?, ?, ?, ?, ?])",
            [
              "%internship%",
              "%engineer%",
              "%developer%",
              "%analyst%",
              "%technician%",
              "%help desk%",
              "%counselor%",
              "%lifeguard%",
            ]
          );
        })
        .countDistinct("participantid as count")
        .first(),
      knex("eventoccurrences as eo")
        .leftJoin(
          "eventtemplates as et",
          "eo.eventtemplateid",
          "et.eventtemplateid"
        )
        .where("eo.eventdatetimestart", ">=", knex.fn.now())
        .orderBy("eo.eventdatetimestart", "asc")
        .limit(3)
        .select(
          "eo.eventoccurrenceid",
          "eo.eventname",
          "eo.eventdatetimestart",
          "eo.eventlocation",
          "et.eventtype",
          "et.eventdescription"
        ),
      // Donors with names if available
      knex("donations as d")
        .leftJoin("participants as p", "d.participantid", "p.participantid")
        .select(
          "d.participantemail as email",
          "p.participantid",
          "p.participantfirstname",
          "p.participantlastname"
        )
        .sum({ totalamount: "d.donationamount" })
        .whereNotNull("d.participantemail")
        .groupBy(
          "d.participantemail",
          "p.participantid",
          "p.participantfirstname",
          "p.participantlastname"
        )
        .orderBy("totalamount", "desc")
        .limit(5),
    ]);

    const totalParticipants = Number(participantsCountRow?.count || 0);
    const totalEvents = Number(eventsCountRow?.count || 0);
    const milestonesAchieved = Number(milestonesCountRow?.count || 0);

    const participantsWithMilestones = Number(
      participantsWithMilestoneRow?.count || 0
    );
    const steamDegreeParticipants = Number(steamDegreeRow?.count || 0);
    const steamJobParticipants = Number(steamJobRow?.count || 0);

    const milestonesSummary = [
      {
        label: "Education",
        title: "Any milestone recorded",
        value: pct(participantsWithMilestones, totalParticipants),
        description:
          "Participants who have at least one milestone logged in the system.",
      },
      {
        label: "STEAM",
        title: "STEAM degrees",
        value: pct(steamDegreeParticipants, totalParticipants),
        description:
          "Participants with degree milestones in STEAM-related fields (engineering, data, art & design, etc.).",
      },
      {
        label: "Careers",
        title: "STEAM jobs & internships",
        value: pct(steamJobParticipants, totalParticipants),
        description:
          "Participants with milestones like internships, analyst roles, lab assistants, and similar positions.",
      },
    ];

    const upcomingEvents = upcomingEventsRows.map((ev) => {
      let dateDisplay = "TBD";
      const dt = ev.eventdatetimestart;
      if (dt instanceof Date && !isNaN(dt)) {
        const month = dt.toLocaleString("en-US", { month: "short" });
        const day = dt.getDate();
        dateDisplay = `${month} ${day}`;
      }

      return {
        type: ev.eventtype || "Event",
        name: ev.eventname,
        dateDisplay,
        location: ev.eventlocation || "TBD",
        description: ev.eventdescription || "No description provided yet.",
      };
    });

    const donors = donorsAgg.map((d) => {
      const total = Number(d.totalamount || 0);
      let level = "Supporter";
      if (total >= DONOR_LEVEL_PLATINUM) level = "Platinum";
      else if (total >= DONOR_LEVEL_GOLD) level = "Gold";
      else if (total >= DONOR_LEVEL_SILVER) level = "Silver";

      const displayName =
        (d.participantfirstname || d.participantlastname)
          ? `${d.participantfirstname || ""} ${d.participantlastname || ""}`.trim()
          : d.email;

      return {
        displayName,
        email: d.email,
        level,
      };
    });

    const stats = {
      totalParticipants,
      totalEvents,
      milestonesAchieved,
    };

    res.render("index", {
      activePage: "home",
      user,
      stats,
      upcomingEvents,
      milestonesSummary,
      donors,
    });
  } catch (err) {
    console.error("Error loading home page:", err);
    res.render("index", {
      activePage: "home",
      user,
      stats: { totalParticipants: 0, totalEvents: 0, milestonesAchieved: 0 },
      upcomingEvents: [],
      milestonesSummary: [],
      donors: [],
    });
  }
});

/* ----- PARTICIPANT PERSONAL DASHBOARD (/me) ----- */
app.get("/me", requireAuth, async (req, res) => {
  const user = req.session.user;

  try {
    const participant = await knex("participants")
      .where("participantid", user.id)
      .first();

    if (!participant) {
      return res.status(404).send("Participant not found.");
    }

    const stats = await buildParticipantStats(
      participant.participantid,
      participant.participantemail
    );

    res.render("participant-dashboard", {
      activePage: "me",
      user,
      participant,
      stats,
    });
  } catch (err) {
    console.error("Error loading participant dashboard:", err);
    res.status(500).send("Error loading your dashboard.");
  }
});

/* --------------------------------------------------
   LOGIN / LOGOUT
-------------------------------------------------- */

// GET /login
app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/");
  }

  res.render("login", {
    activePage: "login",
    error: null,
    formEmail: "",
  });
});

// POST /login (email + password)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const suppliedEmail = (email || "").trim();
  const suppliedPassword = (password || "").trim();

  try {
    const participant = await knex("participants")
      .whereRaw("LOWER(participantemail) = LOWER(?)", [suppliedEmail])
      .first();

    if (!participant) {
      return res.render("login", {
        activePage: "login",
        error: "Invalid email or password.",
        formEmail: suppliedEmail,
      });
    }

    // Prefer "password" column, but fall back to participantpassword if it ever exists
    const dbPasswordRaw =
      participant.password ?? participant.participantpassword ?? "";

    const dbPassword = (dbPasswordRaw || "").trim();

    // If a password is stored, require it to match.
    // If NO password stored (legacy accounts), allow login by email only.
    if (dbPassword) {
      if (!suppliedPassword || suppliedPassword !== dbPassword) {
        return res.render("login", {
          activePage: "login",
          error: "Invalid email or password.",
          formEmail: suppliedEmail,
        });
      }
    }

    const role = (participant.participantrole || "participant").toLowerCase();

    req.session.user = {
      id: participant.participantid,
      email: participant.participantemail,
      name:
        (participant.participantfirstname || "") +
        " " +
        (participant.participantlastname || ""),
      role,
    };

    if (role === "admin") {
      return res.redirect("/admin/dashboard");
    } else {
      return res.redirect("/me");
    }
  } catch (err) {
    console.error("Login error:", err);
    return res.render("login", {
      activePage: "login",
      error: "An error occurred. Please try again.",
      formEmail: suppliedEmail,
    });
  }
});

// GET /logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

/* --------------------------------------------------
   SELF SIGNUP
-------------------------------------------------- */
app.get("/signup", (req, res) => {
  res.render("participants-new", {
    activePage: "signup",
    user: req.session.user || null,
    error: null,
    isSelfSignup: true,
  });
});

app.post("/signup", upload.single("photo"), async (req, res) => {
  const {
    email,
    firstName,
    lastName,
    dob,
    phone,
    city,
    state,
    zip,
    school,
    fieldOfInterest,
    password,
  } = req.body;

  const photoPath = req.file ? `/images/uploads/${req.file.filename}` : null;

  if (!password || password.trim() === "") {
    return res.render("participants-new", {
      activePage: "signup",
      user: req.session.user || null,
      error: "Please choose a password.",
      isSelfSignup: true,
    });
  }

  if ((password || "").trim().length < 8) {
    return res.render("participants-new", {
      activePage: "signup",
      user: req.session.user || null,
      error: "Password must be at least 8 characters.",
      isSelfSignup: true,
    });
  }

  try {
    const existing = await knex("participants")
      .whereRaw("LOWER(participantemail) = LOWER(?)", [email || ""])
      .first();

    if (existing) {
      return res.render("participants-new", {
        activePage: "signup",
        user: req.session.user || null,
        error: "An account with that email already exists. Try logging in.",
        isSelfSignup: true,
      });
    }
  } catch (checkErr) {
    console.error("Error checking existing user during signup:", checkErr);
    return res.render("participants-new", {
      activePage: "signup",
      user: req.session.user || null,
      error: "An error occurred while checking the email. Please try again.",
      isSelfSignup: true,
    });
  }

  try {
    const newId = await getNextParticipantId();

    const [newParticipant] = await knex("participants")
      .insert({
        participantid: newId,
        participantemail: email,
        participantfirstname: firstName,
        participantlastname: lastName,
        participantdob: dob || null,
        participantrole: "participant",
        participantphone: phone || null,
        participantcity: city || null,
        participantstate: state || null,
        participantzip: zip || null,
        participantschooloremployer: school || null,
        participantfieldofinterest: fieldOfInterest || null,
        participantphoto: photoPath,
        password: password.trim(),
      })
      .returning("*");

    const role = (newParticipant.participantrole || "participant").toLowerCase();

    req.session.user = {
      id: newParticipant.participantid,
      email: newParticipant.participantemail,
      name:
        (newParticipant.participantfirstname || "") +
        " " +
        (newParticipant.participantlastname || ""),
      role,
    };

    res.redirect("/me");
  } catch (err) {
    console.error("Error during signup:", err);
    res.render("participants-new", {
      activePage: "signup",
      user: req.session.user || null,
      error: "Error creating your account. Maybe that email already exists?",
      isSelfSignup: true,
    });
  }
});

/* --------------------------------------------------
   ADMIN DASHBOARD
-------------------------------------------------- */
app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  const user = req.session.user;

  try {
    const [
      surveyAgg,
      participantsCountRow,
      steamDegreeRow,
      steamJobRow,
      eventScoresRows,
      donationAgg,
    ] = await Promise.all([
      knex("surveys")
        .count("surveyid as count")
        .avg({ avgsatisfaction: "surveysatisfactionscore" })
        .avg({ avgusefulness: "surveyusefulnessscore" })
        .avg({ avgrecommend: "surveyrecommendationscore" })
        .first(),
      knex("participants").count("participantid as count").first(),
      knex("milestones")
        .where(function () {
          this.whereRaw(
            "LOWER(milestonetitle) LIKE ANY (ARRAY[?, ?, ?, ?, ?, ?, ?, ?, ?])",
            [
              "%bs in%",
              "%ms in%",
              "%bachelor%",
              "%associate%",
              "%engineering%",
              "%computer science%",
              "%data science%",
              "%information systems%",
              "%drafting%",
            ]
          );
        })
        .countDistinct("participantid as count")
        .first(),
      knex("milestones")
        .where(function () {
          this.whereRaw(
            "LOWER(milestonetitle) LIKE ANY (ARRAY[?, ?, ?, ?, ?, ?, ?, ?])",
            [
              "%internship%",
              "%engineer%",
              "%developer%",
              "%analyst%",
              "%technician%",
              "%help desk%",
              "%counselor%",
              "%lifeguard%",
            ]
          );
        })
        .countDistinct("participantid as count")
        .first(),
      knex("surveys")
        .select("eventname")
        .count("* as responsecount")
        .avg({ avgoverall: "surveyoverallscore" })
        .avg({ avgsatisfaction: "surveysatisfactionscore" })
        .groupBy("eventname")
        .orderBy("avgoverall", "desc")
        .limit(5),
      knex("donations")
        .sum({ totalamount: "donationamount" })
        .countDistinct({ donorcount: "participantemail" })
        .first(),
    ]);

    const totalParticipants = Number(participantsCountRow?.count || 0);
    const steamDegreeParticipants = Number(steamDegreeRow?.count || 0);
    const steamJobParticipants = Number(steamJobRow?.count || 0);

    const kpis = {
      avgSatisfaction: Number(surveyAgg?.avgsatisfaction || 0).toFixed(2),
      avgUsefulness: Number(surveyAgg?.avgusefulness || 0).toFixed(2),
      avgRecommend: Number(surveyAgg?.avgrecommend || 0).toFixed(2),
      totalSurveys: Number(surveyAgg?.count || 0),
      steamGradRate: pct(steamDegreeParticipants, totalParticipants),
      steamJobRate: pct(steamJobParticipants, totalParticipants),
      totalDonations: Number(donationAgg?.totalamount || 0).toFixed(2),
      donorCount: Number(donationAgg?.donorcount || 0),
    };

    const topEvents = eventScoresRows.map((ev) => ({
      name: ev.eventname,
      responseCount: Number(ev.responsecount || 0),
      avgOverall: Number(ev.avgoverall || 0).toFixed(2),
      avgSatisfaction: Number(ev.avgsatisfaction || 0).toFixed(2),
    }));

    res.render("admin-dashboard", {
      activePage: "dashboard",
      user,
      kpis,
      topEvents,
    });
  } catch (err) {
    console.error("Error loading admin dashboard:", err);
    res.render("admin-dashboard", {
      activePage: "dashboard",
      user,
      kpis: null,
      topEvents: [],
    });
  }
});

/* --------------------------------------------------
   PARTICIPANTS (LIST + CRUD + DETAIL)
-------------------------------------------------- */

// LIST (admin-only)
app.get("/participants", requireAdmin, async (req, res) => {
  const { search, role } = req.query;

  try {
    let query = knex("participants")
      .select(
        "participantid",
        "participantfirstname",
        "participantlastname",
        "participantemail",
        "participantrole",
        "participantcity",
        "participantstate",
        "participantphoto",
        "participantfieldofinterest"
      )
      .orderBy("participantlastname", "asc");

    if (search && search.trim() !== "") {
      const s = `%${search.toLowerCase()}%`;
      query = query.whereRaw(
        "(LOWER(participantfirstname) LIKE ? OR LOWER(participantlastname) LIKE ? OR LOWER(participantemail) LIKE ?)",
        [s, s, s]
      );
    }

    if (role && role !== "all") {
      query = query.where("participantrole", role);
    }

    const participants = await query;

    res.render("participants-list", {
      activePage: "participants",
      user: req.session.user,
      participants,
      filters: {
        search: search || "",
        role: role || "all",
      },
    });
  } catch (err) {
    console.error("Error loading participants:", err);
    res.status(500).send("Error loading participants.");
  }
});

// ADMIN: add participant (FORM)
app.get("/participants/new", requireAdmin, (req, res) => {
  res.render("participants-new", {
    activePage: "participants",
    user: req.session.user,
    error: null,
    isSelfSignup: false,
  });
});

// ADMIN: add participant (SUBMIT)  ✅ updated
app.post(
  "/participants/new",
  requireAdmin,
  upload.single("photo"),
  async (req, res) => {
    const {
      email,
      firstName,
      lastName,
      dob,
      role,
      phone,
      city,
      state,
      zip,
      school,
      fieldOfInterest,
      password,
    } = req.body;

    const photoPath = req.file ? `/images/uploads/${req.file.filename}` : null;

    try {
      // 1) Check for duplicate email (case-insensitive)
      const existing = await knex("participants")
        .whereRaw("LOWER(participantemail) = LOWER(?)", [email || ""])
        .first();

      if (existing) {
        return res.render("participants-new", {
          activePage: "participants",
          user: req.session.user,
          error: "A participant with that email already exists.",
          isSelfSignup: false,
        });
      }

      // 2) Generate next id
      const newId = await getNextParticipantId();

      // 3) Insert
      await knex("participants").insert({
        participantid: newId,
        participantemail: email,
        participantfirstname: firstName,
        participantlastname: lastName,
        participantdob: dob || null,
        participantrole: role || "participant",
        participantphone: phone || null,
        participantcity: city || null,
        participantstate: state || null,
        participantzip: zip || null,
        participantschooloremployer: school || null,
        participantfieldofinterest: fieldOfInterest || null,
        participantphoto: photoPath,
        password: password ? password.trim() : null,
      });

      res.redirect("/participants");
    } catch (err) {
      console.error("Error creating participant:", err);
      res.render("participants-new", {
        activePage: "participants",
        user: req.session.user,
        error: "Error creating participant.",
        isSelfSignup: false,
      });
    }
  }
);

// ADMIN: participant detail
app.get("/participants/:id", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const participant = await knex("participants")
      .where("participantid", id)
      .first();

    if (!participant) {
      return res.status(404).send("Participant not found");
    }

    const stats = await buildParticipantStats(
      participant.participantid,
      participant.participantemail
    );

    res.render("participant-detail", {
      activePage: "participants",
      user: req.session.user,
      participant,
      stats,
    });
  } catch (err) {
    console.error("Error loading participant detail:", err);
    res.status(500).send("Error loading participant detail.");
  }
});

// ADMIN: edit participant
app.get("/participants/:id/edit", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const participant = await knex("participants")
      .where("participantid", id)
      .first();

    if (!participant) {
      return res.status(404).send("Participant not found");
    }

    res.render("participants-edit", {
      activePage: "participants",
      user: req.session.user,
      participant,
      error: null,
    });
  } catch (err) {
    console.error("Error loading participant:", err);
    res.status(500).send("Error loading participant.");
  }
});

app.post(
  "/participants/:id/edit",
  requireAdmin,
  upload.single("photo"),
  async (req, res) => {
    const id = req.params.id;
    const {
      email,
      firstName,
      lastName,
      dob,
      role,
      phone,
      city,
      state,
      zip,
      school,
      fieldOfInterest,
      removePhoto,
      password,
    } = req.body;

    const file = req.file;

    try {
      const existing = await knex("participants")
        .where("participantid", id)
        .first();

      if (!existing) {
        return res.status(404).send("Participant not found");
      }

      let photoPath = existing.participantphoto;
      if (file) {
        photoPath = `/images/uploads/${file.filename}`;
      } else if (removePhoto === "on") {
        photoPath = null;
      }

      const updateData = {
        participantemail: email,
        participantfirstname: firstName,
        participantlastname: lastName,
        participantdob: dob || null,
        participantrole: role || "participant",
        participantphone: phone || null,
        participantcity: city || null,
        participantstate: state || null,
        participantzip: zip || null,
        participantschooloremployer: school || null,
        participantfieldofinterest: fieldOfInterest || null,
        participantphoto: photoPath,
      };

      if (password && password.trim() !== "") {
        updateData.password = password.trim();
      }

      await knex("participants").where("participantid", id).update(updateData);

      res.redirect("/participants/" + id);
    } catch (err) {
      console.error("Error updating participant:", err);
      res.status(500).send("Error updating participant.");
    }
  }
);

// ADMIN: delete participant
app.post("/participants/:id/delete", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    await knex("participants").where("participantid", id).del();
    res.redirect("/participants");
  } catch (err) {
    console.error("Error deleting participant:", err);
    res.status(500).send("Error deleting participant.");
  }
});

/* --------------------------------------------------
   EVENTS (LIST + CREATE + DETAIL + EDIT + DELETE)
-------------------------------------------------- */

// PUBLIC events list (no login required)
app.get("/events", async (req, res) => {
  try {
    const eventTemplates = await knex("eventtemplates")
      .select(
        "eventtemplateid",
        "eventname",
        "eventtype",
        "eventdescription",
        "eventrecurrencepattern",
        "eventdefaultcapacity"
      )
      .orderBy("eventname", "asc");

    res.render("events-list", {
      activePage: "events",
      user: req.session.user || null,
      eventTemplates,
    });
  } catch (err) {
    console.error("Error loading events:", err);
    res.status(500).send("Error loading events.");
  }
});

// ADMIN: create event template (form)
app.get("/events/new", requireAdmin, (req, res) => {
  res.render("events-new", {
    activePage: "events",
    user: req.session.user,
    error: null,
    formData: {
      eventName: "",
      eventType: "",
      eventDescription: "",
      recurrencePattern: "",
      defaultCapacity: "",
    },
  });
});

// ADMIN: create event template (submit)
app.post("/events/new", requireAdmin, async (req, res) => {
  const {
    eventName,
    eventType,
    eventDescription,
    recurrencePattern,
    defaultCapacity,
  } = req.body;

  const trimmedName = (eventName || "").trim();

  if (!trimmedName) {
    return res.render("events-new", {
      activePage: "events",
      user: req.session.user,
      error: "Event name is required.",
      formData: {
        eventName,
        eventType,
        eventDescription,
        recurrencePattern,
        defaultCapacity,
      },
    });
  }

  try {
    const newId = await getNextEventTemplateId();

    await knex("eventtemplates").insert({
      eventtemplateid: newId,
      eventname: trimmedName,
      eventtype: eventType || null,
      eventdescription: eventDescription || null,
      eventrecurrencepattern: recurrencePattern || null,
      eventdefaultcapacity:
        defaultCapacity && defaultCapacity !== ""
          ? Number(defaultCapacity)
          : null,
    });

    res.redirect("/events");
  } catch (err) {
    console.error("Error creating event template:", err);
    res.render("events-new", {
      activePage: "events",
      user: req.session.user,
      error: "Error creating event template. Please try again.",
      formData: {
        eventName,
        eventType,
        eventDescription,
        recurrencePattern,
        defaultCapacity,
      },
    });
  }
});

// ADMIN: event detail
app.get("/events/:id", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const template = await knex("eventtemplates")
      .where("eventtemplateid", id)
      .first();

    if (!template) {
      return res.status(404).send("Event template not found");
    }

    const stats = await buildEventStats(id);

    res.render("event-detail", {
      activePage: "events",
      user: req.session.user,
      eventTemplate: template,
      stats,
    });
  } catch (err) {
    console.error("Error loading event detail:", err);
    res.status(500).send("Error loading event detail.");
  }
});

// ADMIN: edit event (form)
app.get("/events/:id/edit", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const template = await knex("eventtemplates")
      .where("eventtemplateid", id)
      .first();

    if (!template) {
      return res.status(404).send("Event template not found");
    }

    res.render("events-edit", {
      activePage: "events",
      user: req.session.user,
      eventTemplate: template,
      error: null,
    });
  } catch (err) {
    console.error("Error loading event for edit:", err);
    res.status(500).send("Error loading event for edit.");
  }
});

// ADMIN: edit event (submit)
app.post("/events/:id/edit", requireAdmin, async (req, res) => {
  const id = req.params.id;
  const {
    eventName,
    eventType,
    eventDescription,
    recurrencePattern,
    defaultCapacity,
  } = req.body;

  try {
    await knex("eventtemplates")
      .where("eventtemplateid", id)
      .update({
        eventname: eventName,
        eventtype: eventType || null,
        eventdescription: eventDescription || null,
        eventrecurrencepattern: recurrencePattern || null,
        eventdefaultcapacity:
          defaultCapacity && defaultCapacity !== ""
            ? Number(defaultCapacity)
            : null,
      });

    res.redirect("/events/" + id);
  } catch (err) {
    console.error("Error updating event:", err);
    res.status(500).send("Error updating event.");
  }
});

// ADMIN: delete event
app.post("/events/:id/delete", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    await knex("eventtemplates").where("eventtemplateid", id).del();
    res.redirect("/events");
  } catch (err) {
    console.error("Error deleting event:", err);
    res.status(500).send("Error deleting event.");
  }
});

/* --------------------------------------------------
   DONATIONS
-------------------------------------------------- */

app.get("/donations/new", (req, res) => {
  res.redirect("/donate");
});

app.get("/donate", (req, res) => {
  res.render("donations-new", {
    activePage: "donate",
    user: req.session.user || null,
    error: null,
    success: null,
  });
});

app.post("/donate", async (req, res) => {
  const { email, amount } = req.body;

  if (!amount || isNaN(parseFloat(amount))) {
    return res.render("donations-new", {
      activePage: "donate",
      user: req.session.user || null,
      error: "Please enter a valid donation amount.",
      success: null,
    });
  }

  try {
    let participantId = null;
    if (req.session.user && req.session.user.id) {
      participantId = req.session.user.id;
    }

    await knex("donations").insert({
      participantemail: email || null,
      donationdate: new Date(),
      donationamount: parseFloat(amount),
      participantid: participantId,
    });

    return res.render("donations-new", {
      activePage: "donate",
      user: req.session.user || null,
      error: null,
      success: "Thank you for your donation! 💜",
    });
  } catch (err) {
    console.error("Error recording donation:", err);
    return res.render("donations-new", {
      activePage: "donate",
      user: req.session.user || null,
      error: "There was an error recording your donation.",
      success: null,
    });
  }
});

app.get("/admin/donations", requireAdmin, async (req, res) => {
  try {
    const [donations, donationSummary] = await Promise.all([
      knex("donations as d")
        .leftJoin("participants as p", "d.participantid", "p.participantid")
        .select(
          "d.donationid",
          "d.participantemail",
          "d.donationdate",
          "d.donationamount",
          "d.participantid",
          "p.participantfirstname",
          "p.participantlastname"
        )
        .orderBy("d.donationdate", "desc")
        .limit(200),
      knex("donations")
        .sum({ totalamount: "donationamount" })
        .count("* as donationcount")
        .first(),
    ]);

    res.render("admin-donations", {
      activePage: "admin-donations",
      user: req.session.user,
      donations,
      donationSummary: {
        totalAmount: Number(donationSummary?.totalamount || 0),
        donationCount: Number(donationSummary?.donationcount || 0),
      },
    });
  } catch (err) {
    console.error("Error loading donations:", err);
    res.status(500).send("Error loading donations.");
  }
});

/* --------------------------------------------------
   ADMIN DASHBOARDS (TABLEAU EMBED)
-------------------------------------------------- */
app.get("/admin/dashboards", requireAdmin, (req, res) => {
  res.render("admin-dashboards", {
    activePage: "admin-dashboards",
    user: req.session.user,
  });
});

/* --------------------------------------------------
   FUN / MISC
-------------------------------------------------- */
app.get("/teapot", (req, res) => {
  res.status(418).send("I'm a little teapot, short and stout. ☕");
});

app.get("/dashboard/public", (req, res) => {
  res.redirect("/");
});

/* --------------------------------------------------
   START SERVER
-------------------------------------------------- */
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log("The server is listening on port", port);
});
