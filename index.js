// Load environment variables from .env into process.env
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const knexLib = require("knex");
const bcrypt = require("bcrypt");

// How many salt rounds to use when hashing passwords with bcrypt
const SALT_ROUNDS = 10;
const app = express();

/* --------------------------------------------------
   VIEW ENGINE
   - Use EJS templates located in /views
-------------------------------------------------- */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* --------------------------------------------------
   STATIC FILES + UPLOADS
   - Serve /public as static
   - Handle uploads into /images/uploads
-------------------------------------------------- */
const uploadRoot = path.join(__dirname, "images");
const uploadDir = path.join(uploadRoot, "uploads");

// Ensure base image directory exists
if (!fs.existsSync(uploadRoot)) fs.mkdirSync(uploadRoot);
// Ensure uploads subdirectory exists
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Configure how multer stores uploaded files
const storage = multer.diskStorage({
  // Save all uploaded files into uploadDir
  destination: (req, file, cb) => cb(null, uploadDir),
  // Name files with a timestamp + original filename (reduces conflicts)
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

// Multer instance using the above disk storage
const upload = multer({ storage });

// Serve any file under /images from the images folder
app.use("/images", express.static(uploadRoot));

// Serve rotating hero/carousel images from a specific public folder
app.use(
  "/images/rotate-images",
  express.static(path.join(__dirname, "public", "images", "rotate-images"))
);

// Serve anything under /public (CSS, JS, etc.)
app.use(express.static("public"));

/* --------------------------------------------------
   SESSION
   - Simple in-memory session (sufficient for class project)
-------------------------------------------------- */
app.use(
  session({
    // Secret used to sign the session ID cookie
    secret: process.env.SESSION_SECRET || "fallback-secret-key",
    resave: false,          // Don't re-save unchanged sessions
    saveUninitialized: false, // Don't create sessions until we store data
  })
);

/* --------------------------------------------------
   CONSTANTS (DONOR LEVELS)
   - Read from env or fallback defaults
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
   - Parse URL-encoded form submissions into req.body
-------------------------------------------------- */
app.use(express.urlencoded({ extended: true }));

/* --------------------------------------------------
   DATABASE (Postgres intex)
   - Connection to RDS Postgres, schema "ellarises"
-------------------------------------------------- */
const knex = knexLib({
  client: "pg",
  connection: {
    host: "intexdb.c70cumo8kg8k.us-east-2.rds.amazonaws.com",
    user: "postgres",
    password: "intexpassword",
    database: "intexdb",
    port: 5432,
    ssl: { rejectUnauthorized: false }, // accept RDS cert without CA chain
  },
  searchPath: ["ellarises"], // default schema
});

// Quick connection sanity check on startup
knex
  .raw("SELECT 1")
  .then(() => console.log("✅ Connected to PostgreSQL (intex)"))
  .catch((err) => console.error("❌ DB connection error:", err.message));

/* --------------------------------------------------
   AUTH HELPERS
-------------------------------------------------- */

// Middleware: attach logged-in user (if any) to res.locals so EJS can use it
function attachUser(req, res, next) {
  res.locals.user = req.session.user || null;
  next();
}
app.use(attachUser);

// Middleware: require *any* logged-in user
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

// Middleware: require admin role for protected admin routes
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Access denied. Admins only.");
  }
  next();
}

// Helper: percentage display as a string like "67%"; returns "—" if total is 0
function pct(part, whole) {
  if (!whole || whole === 0) return "—";
  return Math.round((part / whole) * 100) + "%";
}

/* --------------------------------------------------
   ID HELPERS (WORKAROUND BROKEN SEQUENCES)
   - Manually generate next ID by max + 1
   - This avoids issues if DB sequences are not aligned
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
   - Compute rollup stats for participants & events
-------------------------------------------------- */

/**
 * Build a stats object for a single participant:
 * - donations totals & recent donations
 * - survey averages & recent surveys
 * - milestones (education / career)
 * - registrations & attendance rate
 *
 * Participant may be matched by ID or by email, to tolerate older data.
 */
async function buildParticipantStats(participantId, participantEmail) {
  const emailLower = participantEmail ? participantEmail.toLowerCase() : null;

  // Helper for donations: match either by participantid OR by (lowercased) email
  const donationsWhere = (qb) => {
    if (participantId) qb.where("participantid", participantId);
    if (emailLower) qb.orWhereRaw("LOWER(participantemail) = ?", [emailLower]);
  };

  // Helper for surveys: only email is available on the surveys table
  const emailWhere = (qb) => {
    if (emailLower) qb.whereRaw("LOWER(participantemail) = ?", [emailLower]);
    else qb.whereRaw("1 = 0"); // no email -> intentionally match nothing
  };

  // Run several queries in parallel for performance
  const [
    donationAgg,
    recentDonations,
    surveyAgg,
    recentSurveys,
    milestones,
    regTotalRow,
    regAttendedRow,
  ] = await Promise.all([
    // Donation aggregates: sum, count, first/last dates
    knex("donations")
      .modify(donationsWhere)
      .sum("donationamount as totalamount")
      .count("donationid as donationcount")
      .min("donationdate as firstdonation")
      .max("donationdate as lastdonation")
      .first(),

    // Recent individual donations
    knex("donations")
      .modify(donationsWhere)
      .orderBy("donationdate", "desc")
      .limit(5)
      .select("donationdate", "donationamount"),

    // Survey aggregates
    knex("surveys")
      .modify(emailWhere)
      .count("surveyid as totalsurveys")
      .avg("surveysatisfactionscore as avgsatisfaction")
      .avg("surveyusefulnessscore as avgusefulness")
      .avg("surveyrecommendationscore as avgrecommend")
      .avg("surveyoverallscore as avgoverall")
      .first(),

    // Recent surveys (for dashboard list)
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

    // Milestones, matched by participantid OR email
    knex("milestones")
      .modify((qb) => {
        if (participantId) qb.where("participantid", participantId);
        if (emailLower) qb.orWhereRaw("LOWER(participantemail) = ?", [emailLower]);
      })
      .orderBy("milestonedate", "desc")
      .limit(10),

    // Total registrations (to compute attendance rate)
    knex("registrations")
      .modify((qb) => {
        if (participantId) qb.where("participantid", participantId);
        else if (emailLower) qb.whereRaw("LOWER(participantemail) = ?", [emailLower]);
        else qb.whereRaw("1 = 0");
      })
      .count("registrationid as totalregistrations")
      .first(),

    // Registrations that were actually attended
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

  // Normalize return structure to be safe for EJS templates
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

/**
 * Build stats for a given event template:
 * - gather all occurrences
 * - compute overall registrations / attendance / survey scores
 */
async function buildEventStats(eventTemplateId) {
  // All occurrences for the template
  const occurrences = await knex("eventoccurrences")
    .where("eventtemplateid", eventTemplateId)
    .orderBy("eventdatetimestart", "desc");

  // Extract IDs for use in whereIn()
  const occIds = occurrences.map((o) => o.eventoccurrenceid);

  let totalRegistrations = 0;
  let totalAttended = 0;
  let totalSurveys = 0;
  let avgSatisfaction = 0;
  let avgOverall = 0;

  if (occIds.length > 0) {
    // Only run these queries if there are occurrences
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

  // Normalize for template
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

/* ----- API: carousel images -----
   - Returns list of image URLs under /public/images/rotate-images
   - Used by front-end carousel JS
-------------------------------------------------- */
app.get("/api/carousel-images", (req, res) => {
  const carouselDir = path.join(__dirname, "public", "images", "rotate-images");

  try {
    const files = fs.readdirSync(carouselDir);
    const imageExtensions = [".jpg", ".jpeg", ".png", ".gif", ".webp"];

    // Only include files with image extensions
    const images = files
      .filter((file) =>
        imageExtensions.includes(path.extname(file).toLowerCase())
      )
      .map((file) => `/images/rotate-images/${file}`);

    res.json({ images });
  } catch (err) {
    console.error("Error reading carousel images:", err);
    // Fail gracefully with an empty array so the front-end doesn't crash
    res.json({ images: [] });
  }
});

/* ----- HOME / LANDING PAGE -----
   - Pulls high-level stats, upcoming events, and top donors
   - Renders index.ejs
-------------------------------------------------- */
app.get("/", async (req, res) => {
  const user = req.session.user || null;

  try {
    // Run many aggregate queries in parallel for performance
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
      // Total participants
      knex("participants").count("participantid as count").first(),
      // Total event occurrences
      knex("eventoccurrences").count("eventoccurrenceid as count").first(),
      // Total milestones recorded
      knex("milestones").count("milestoneid as count").first(),
      // How many participants have at least one milestone
      knex("milestones").countDistinct("participantid as count").first(),
      // Participants with "STEAM-ish" degree milestones
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
      // Participants with "STEAM-ish" job / internship milestones
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
      // Next 3 upcoming event occurrences
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
      // Top 5 donors by total amount; show name if known
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

    // High-level impact stats for the landing page
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

    // Transform upcoming events to a simpler shape for the template
    const upcomingEvents = upcomingEventsRows.map((ev) => {
      let dateDisplay = "TBD";
      const dt = ev.eventdatetimestart;

      // Safely attempt to format the date
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

    // Map donor aggregates to nice display objects
    const donors = donorsAgg.map((d) => {
      const total = Number(d.totalamount || 0);
      let level = "Supporter";

      if (total >= DONOR_LEVEL_PLATINUM) level = "Platinum";
      else if (total >= DONOR_LEVEL_GOLD) level = "Gold";
      else if (total >= DONOR_LEVEL_SILVER) level = "Silver";

      const displayName =
        (d.participantfirstname || d.participantlastname)
          ? `${d.participantfirstname || ""} ${d.participantlastname || ""}`.trim()
          : d.email; // Fallback to email if no name on file

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

    // Render home page with all assembled data
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
    // If anything fails, show page with safe defaults instead of crashing
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

/* ----- PARTICIPANT PERSONAL DASHBOARD (/me)
   - Private page for the logged-in participant
   - Uses buildParticipantStats to show their donations/surveys/etc.
-------------------------------------------------- */
app.get("/me", requireAuth, async (req, res) => {
  const user = req.session.user;

  try {
    // Look up participant row for this session's user
    const participant = await knex("participants")
      .where("participantid", user.id)
      .first();

    if (!participant) {
      return res.status(404).send("Participant not found.");
    }

    // Build stats object for this participant
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
// - If already logged in, redirect to home
// - Otherwise show login form
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

// POST /login
// - Email + password form
// - Supports legacy accounts (email-only) AND hashed passwords
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const suppliedEmail = (email || "").trim();
  const suppliedPassword = (password || "").trim();

  try {
    // Find participant by email (case-insensitive)
    const participant = await knex("participants")
      .whereRaw("LOWER(participantemail) = LOWER(?)", [suppliedEmail])
      .first();

    if (!participant) {
      // Do not reveal whether email exists; generic error
      return res.render("login", {
        activePage: "login",
        error: "Invalid email or password.",
        formEmail: suppliedEmail,
      });
    }

    // Prefer the new `password` column; fall back to old `participantpassword` if present
    const dbPasswordRaw =
      participant.password ?? participant.participantpassword ?? "";

    const dbPassword = (dbPasswordRaw || "").trim();

    // If a password is stored, require it to match.
    // If NO password stored (legacy accounts), allow login by email only.
    if (dbPassword) {
      // If password is required but not supplied, fail
      if (!suppliedPassword) {
        return res.render("login", {
          activePage: "login",
          error: "Invalid email or password.",
          formEmail: suppliedEmail,
        });
      }

      let passwordMatches = false;

      // If it looks like a bcrypt hash (starts with "$2")
      if (dbPassword.startsWith("$2")) {
        // Compare hashed password
        passwordMatches = await bcrypt.compare(suppliedPassword, dbPassword);
      } else {
        // Legacy plain-text password (not ideal, but kept for backwards compatibility)
        passwordMatches = suppliedPassword === dbPassword;
      }

      if (!passwordMatches) {
        // Generic error to avoid leaking password correctness
        return res.render("login", {
          activePage: "login",
          error: "Invalid email or password.",
          formEmail: suppliedEmail,
        });
      }
    }

    const role = (participant.participantrole || "participant").toLowerCase();

    // Store minimal user info in session
    req.session.user = {
      id: participant.participantid,
      email: participant.participantemail,
      name:
        (participant.participantfirstname || "") +
        " " +
        (participant.participantlastname || ""),
      role,
    };

    // Redirect based on role
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
// - Destroy session and redirect back to login
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

/* --------------------------------------------------
   SELF SIGNUP
   - Public self-registration for participants
-------------------------------------------------- */

// Show the self-signup form (reuses participants-new view)
app.get("/signup", (req, res) => {
  res.render("participants-new", {
    activePage: "signup",
    user: req.session.user || null,
    error: null,
    isSelfSignup: true,
  });
});

// Handle self-signup form submission
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

  // Basic password validation (required, non-empty)
  if (!password || password.trim() === "") {
    return res.render("participants-new", {
      activePage: "signup",
      user: req.session.user || null,
      error: "Please choose a password.",
      isSelfSignup: true,
    });
  }

  // Minimum password length for basic security
  if ((password || "").trim().length < 8) {
    return res.render("participants-new", {
      activePage: "signup",
      user: req.session.user || null,
      error: "Password must be at least 8 characters.",
      isSelfSignup: true,
    });
  }

  // Check for existing account with same email
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

  // Actually create the new participant
  try {
    const newId = await getNextParticipantId();
    const hashedPassword = await bcrypt.hash(password.trim(), SALT_ROUNDS);

    // Insert and return the new row (Postgres .returning("*"))
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
        password: hashedPassword, // Save bcrypt hash, not plaintext
      })
      .returning("*");

    const role = (newParticipant.participantrole || "participant").toLowerCase();

    // Log them in immediately after signup
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
   ADMIN DASHBOARD (high-level KPIs)
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
      // Overall survey info
      knex("surveys")
        .count("surveyid as count")
        .avg({ avgsatisfaction: "surveysatisfactionscore" })
        .avg({ avgusefulness: "surveyusefulnessscore" })
        .avg({ avgrecommend: "surveyrecommendationscore" })
        .first(),
      // Total participants
      knex("participants").count("participantid as count").first(),
      // Participants with STEAM-like degree milestones
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
      // Participants with STEAM-like jobs / internships
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
      // Top 5 events by overall score
      knex("surveys")
        .select("eventname")
        .count("* as responsecount")
        .avg({ avgoverall: "surveyoverallscore" })
        .avg({ avgsatisfaction: "surveysatisfactionscore" })
        .groupBy("eventname")
        .orderBy("avgoverall", "desc")
        .limit(5),
      // Donation totals and number of distinct donors
      knex("donations")
        .sum({ totalamount: "donationamount" })
        .countDistinct({ donorcount: "participantemail" })
        .first(),
    ]);

    const totalParticipants = Number(participantsCountRow?.count || 0);
    const steamDegreeParticipants = Number(steamDegreeRow?.count || 0);
    const steamJobParticipants = Number(steamJobRow?.count || 0);

    // KPI block for admin dashboard
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

    // Per-event summary for "top events" card
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

// LIST (admin-only) - /participants
// - Supports search (name/email) and role filter (admin/participant)
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

    // Case-insensitive search across first name, last name, or email
    if (search && search.trim() !== "") {
      const s = `%${search.toLowerCase()}%`;
      query = query.whereRaw(
        "(LOWER(participantfirstname) LIKE ? OR LOWER(participantlastname) LIKE ? OR LOWER(participantemail) LIKE ?)",
        [s, s, s]
      );
    }

    // Role filter (all / participant / admin)
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

// ADMIN: add participant (FORM) - manual admin creation
app.get("/participants/new", requireAdmin, (req, res) => {
  res.render("participants-new", {
    activePage: "participants",
    user: req.session.user,
    error: null,
    isSelfSignup: false,
  });
});

// ADMIN: add participant (SUBMIT)
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

      // 2) Generate next custom ID
      const newId = await getNextParticipantId();

      // 3) Hash password if provided (admins can create accounts with or without passwords)
      let hashedPassword = null;
      if (password && password.trim() !== "") {
        hashedPassword = await bcrypt.hash(password.trim(), SALT_ROUNDS);
      }

      // 4) Insert participant row
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
        password: hashedPassword,
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

// ADMIN: participant detail page with stats
app.get("/participants/:id", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const participant = await knex("participants")
      .where("participantid", id)
      .first();

    if (!participant) {
      return res.status(404).send("Participant not found");
    }

    // Build stats for this participant (donations, surveys, etc.)
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

// ADMIN: edit participant (FORM)
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

// ADMIN: edit participant (SUBMIT)
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

      // Start with existing photo; then override based on upload / remove flag
      let photoPath = existing.participantphoto;
      if (file) {
        photoPath = `/images/uploads/${file.filename}`;
      } else if (removePhoto === "on") {
        photoPath = null;
      }

      // Base update payload (no password yet)
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

      // If admin entered a new password, hash and update it
      if (password && password.trim() !== "") {
        updateData.password = await bcrypt.hash(password.trim(), SALT_ROUNDS);
      }

      await knex("participants").where("participantid", id).update(updateData);

      res.redirect("/participants/" + id);
    } catch (err) {
      console.error("Error updating participant:", err);
      res.status(500).send("Error updating participant.");
    }
  }
);

// ADMIN: delete participant (no cascade here; foreign keys may enforce behavior)
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

// PUBLIC events list (no auth)
// - Lists event templates (not specific occurrences)
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

  // Require an event name
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

// ADMIN: event detail with stats across all occurrences
app.get("/events/:id", requireAdmin, async (req, res) => {
  const id = req.params.id;

  try {
    const template = await knex("eventtemplates")
      .where("eventtemplateid", id)
      .first();

    if (!template) {
      return res.status(404).send("Event template not found");
    }

    // Build aggregated stats for this event template
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

// ADMIN: edit event template (form)
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

// ADMIN: edit event template (submit)
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

// ADMIN: delete event template
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

// Shortcut: redirect /donations/new -> /donate
app.get("/donations/new", (req, res) => {
  res.redirect("/donate");
});

// Show donation form (public)
app.get("/donate", (req, res) => {
  res.render("donations-new", {
    activePage: "donate",
    user: req.session.user || null,
    error: null,
    success: null,
  });
});

// Handle donation submission
app.post("/donate", async (req, res) => {
  const { email, amount } = req.body;

  // Validate amount is numeric
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

    // If a logged-in participant donates, capture their participantid
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

// ADMIN: view donation list + summary
app.get("/admin/donations", requireAdmin, async (req, res) => {
  try {
    const [donations, donationSummary] = await Promise.all([
      // List of recent donations with optional participant name
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
      // Aggregate donation stats
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
  // Simple view that contains Tableau embed iframes
  res.render("admin-dashboards", {
    activePage: "admin-dashboards",
    user: req.session.user,
  });
});

/* --------------------------------------------------
   FUN / MISC
-------------------------------------------------- */

// A fun little Easter-egg route
app.get("/teapot", (req, res) => {
  res.status(418).send("I'm a little teapot, short and stout. ☕");
});

// Public-facing impact metrics link simply redirects to home for now
app.get("/dashboard/public", (req, res) => {
  res.redirect("/");
});

/* --------------------------------------------------
   START SERVER
-------------------------------------------------- */
const port = process.env.PORT || 3001;

// Start Express server
app.listen(port, () => {
  console.log("The server is listening on port", port);
});
