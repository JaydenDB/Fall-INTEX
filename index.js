require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const multer = require("multer");

const app = express();

// ----- VIEW ENGINE -----
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// ----- STATIC FILES -----
const uploadRoot = path.join(__dirname, "images");
const uploadDir = path.join(uploadRoot, "uploads");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

const upload = multer({ storage });

app.use("/images", express.static(uploadRoot));
app.use(express.static("public"));

// ----- SESSION -----
app.use(
  session({
    secret: process.env.SESSION_SECRET || "fallback-secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// ----- BODY PARSING -----
app.use(express.urlencoded({ extended: true }));

// ----- DATABASE (Postgres intex) -----
const knex = require("knex")({
  client: "pg",
  connection: {
    host: "intexdb.c70cumo8kg8k.us-east-2.rds.amazonaws.com",
    user: "postgres",
    password: "intexpassword",
    database: "postgres",
    port: 5432,
    ssl: { rejectUnauthorized: false }
  },
});

// quick connection test
knex
  .raw("SELECT 1")
  .then(() => console.log("✅ Connected to PostgreSQL (intex)"))
  .catch((err) => console.error("❌ DB connection error:", err.message));

// ----- AUTH HELPERS -----

// attach user from session to res.locals so EJS can use `user`
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

// ----- ROUTES -----

// HOME / LANDING PAGE (public, fully dynamic)
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
      // STEAM degree-ish milestones
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
      // job / internship-type milestones
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
      // upcoming events from EventOccurrences + EventTemplates
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
      // donors aggregated by email
      knex("donations")
        .select("participantemail")
        .sum({ totalamount: "donationamount" })
        .whereNotNull("participantemail")
        .groupBy("participantemail")
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

    // Build milestone summary cards for home page
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

    // Upcoming events view model
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

    // Donors list (simple levels based on total amount)
    const donors = donorsAgg.map((d) => {
      const total = Number(d.totalamount || 0);
      let level = "Supporter";
      if (total >= 2000) level = "Platinum";
      else if (total >= 1000) level = "Gold";
      else if (total >= 500) level = "Silver";

      return {
        name: d.participantemail,
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

// ----- LOGIN / LOGOUT -----

// GET /login -> show login form
app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/");
  }

  res.render("login", {
    activePage: "login",
    error: null,
  });
});

// POST /login -> email-only login using Participants table
app.post("/login", async (req, res) => {
  const { email } = req.body;

  try {
    const participant = await knex("participants")
      .whereRaw("LOWER(participantemail) = LOWER(?)", [email])
      .first();

    if (!participant) {
      return res.render("login", {
        activePage: "login",
        error: "No account found with that email.",
      });
    }

    req.session.user = {
      id: participant.participantid,
      email: participant.participantemail,
      name:
        (participant.participantfirstname || "") +
        " " +
        (participant.participantlastname || ""),
      role: participant.participantrole || "participant",
    };

    if (req.session.user.role === "admin") {
      return res.redirect("/admin/dashboard");
    } else {
      return res.redirect("/");
    }
  } catch (err) {
    console.error("Login error:", err);
    return res.render("login", {
      activePage: "login",
      error: "An error occurred. Please try again.",
    });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ----- SELF SIGNUP (participants create their own accounts) -----

// GET /signup
app.get("/signup", (req, res) => {
  res.render("participants-new", {
    activePage: "signup",
    user: req.session.user || null,
    error: null,
    isSelfSignup: true,
  });
});

// POST /signup
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
  } = req.body;

  const photoPath = req.file ? `/images/uploads/${req.file.filename}` : null;

  try {
    const [newParticipant] = await knex("participants")
      .insert({
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
      })
      .returning("*");

    // auto-log them in
    req.session.user = {
      id: newParticipant.participantid,
      email: newParticipant.participantemail,
      name:
        (newParticipant.participantfirstname || "") +
        " " +
        (newParticipant.participantlastname || ""),
      role: newParticipant.participantrole || "participant",
    };

    res.redirect("/");
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

// ----- ADMIN DASHBOARD (dynamic KPIs) -----
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

// ----- PARTICIPANTS (view for all logged-in users; add/edit/delete for admins) -----
app.get("/participants", requireAuth, async (req, res) => {
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
        "participantphoto"
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

// ADMIN: add participant
app.get("/participants/new", requireAdmin, (req, res) => {
  res.render("participants-new", {
    activePage: "participants",
    user: req.session.user,
    error: null,
    isSelfSignup: false,
  });
});

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
    } = req.body;

    const photoPath = req.file ? `/images/uploads/${req.file.filename}` : null;

    try {
      await knex("participants").insert({
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
      });

      res.redirect("/participants");
    } catch (err) {
      console.error("Error creating participant:", err);
      res.render("participants-new", {
        activePage: "participants",
        user: req.session.user,
        error: "Error creating participant. Maybe email already exists?",
        isSelfSignup: false,
      });
    }
  }
);

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

      await knex("participants")
        .where("participantid", id)
        .update({
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
        });

      res.redirect("/participants");
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

// ----- EVENTS (basic list from EventTemplates) -----
app.get("/events", requireAuth, async (req, res) => {
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
      user: req.session.user,
      eventTemplates,
    });
  } catch (err) {
    console.error("Error loading events:", err);
    res.status(500).send("Error loading events.");
  }
});

// ----- DONATIONS (public donate page + admin view) -----

// Simple redirect so the CTA in index.ejs works either way
app.get("/donations/new", (req, res) => {
  res.redirect("/donate");
});

// Public donation page
app.get("/donate", (req, res) => {
  res.render("donations-new", {
    activePage: "donate",
    user: req.session.user || null,
    error: null,
    success: null,
  });
});

app.post("/donate", async (req, res) => {
  const { email, amount, nameOnCard, cardNumber, expMonth, expYear, cvv } =
    req.body;

  if (!amount || isNaN(parseFloat(amount))) {
    return res.render("donations-new", {
      activePage: "donate",
      user: req.session.user || null,
      error: "Please enter a valid donation amount.",
      success: null,
    });
  }

  try {
    await knex("donations").insert({
      participantemail: email || null,
      donationdate: new Date(),
      donationamount: parseFloat(amount),
      participantid: null,
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

// Admin view of donations
app.get("/admin/donations", requireAdmin, async (req, res) => {
  try {
    const [donations, donationSummary] = await Promise.all([
      knex("donations")
        .select(
          "donationid",
          "participantemail",
          "donationdate",
          "donationamount",
          "participantid"
        )
        .orderBy("donationdate", "desc")
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

// ----- ADMIN: EMBED DASHBOARD (Tableau, etc.) -----
app.get("/admin/dashboards", requireAdmin, (req, res) => {
  res.render("admin-dashboards", {
    activePage: "admin-dashboards",
    user: req.session.user,
  });
});

// HTTP 418 route for IS 404 requirement
app.get("/teapot", (req, res) => {
  res.status(418).send("I'm a little teapot, short and stout. ☕");
});

// ----- PUBLIC DASHBOARD CTA FALLBACK -----
app.get("/dashboard/public", (req, res) => {
  res.redirect("/");
});

// ----- START SERVER -----
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log("The server is listening on port", port);
});
