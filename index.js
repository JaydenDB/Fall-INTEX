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
  filename: (req, file, cb) => cb(null, file.originalname),
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

// ----- DATABASE (RDS intexdb) -----
const knex = require("knex")({
  client: "pg",
  connection: {
    host:
      process.env.DB_HOST ||
      "intexdb.c70cumo8kg8k.us-east-2.rds.amazonaws.com",
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "intexpassword",
    database: process.env.DB_NAME || "intexdb",
    port: process.env.DB_PORT || 5432,
    ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
  },
});

// quick connection test
knex
  .raw("SELECT 1")
  .then(() => console.log("✅ Connected to PostgreSQL (RDS intexdb)"))
  .catch((err) => console.error("❌ DB connection error:", err.message));

// ----- DEV-ONLY DEFAULT ADMIN USER -----
const DEFAULT_ADMIN = {
  id: 0,
  email: "admin@example.com",
  name: "Demo Admin",
  role: "admin",
};

// ----- AUTH HELPERS -----
function attachUser(req, res, next) {
  // DEV-ONLY: automatically log everyone in as admin if no session user
  if (!req.session.user) {
    req.session.user = { ...DEFAULT_ADMIN };
  }

  res.locals.user = req.session.user;
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

// ----- ROUTES -----

// HOME / LANDING PAGE (public)
app.get("/", async (req, res) => {
  const user = req.session.user || null;

  // TODO: replace with real counts from DB
  const stats = {
    totalParticipants: 120,
    totalEvents: 18,
    milestonesAchieved: 75,
  };

  const upcomingEvents = [
    {
      type: "Workshop",
      name: "STEAM Robotics Lab",
      dateDisplay: "Jan 10",
      location: "UVU Campus",
      description:
        "Hands-on robotics and coding activities for middle school girls.",
    },
    {
      type: "Summit",
      name: "Ella Rises Summer Summit",
      dateDisplay: "Jun 22",
      location: "BYU",
      description:
        "A full-day summit that combines art, STEAM, and college exploration.",
    },
    {
      type: "Music",
      name: "Mariachi Performance Night",
      dateDisplay: "Mar 5",
      location: "Community Center",
      description:
        "Showcase of our all-female mariachi students and their progress.",
    },
  ];

  const milestonesSummary = [
    {
      label: "Education",
      title: "College enrollment",
      value: "68%",
      description:
        "Participants who report enrolling in any post-secondary program.",
    },
    {
      label: "STEAM",
      title: "STEAM majors",
      value: "41%",
      description:
        "Participants choosing a STEAM-related major after high school.",
    },
    {
      label: "Careers",
      title: "STEAM jobs",
      value: "27%",
      description:
        "Participants who report working in STEAM fields post-college.",
    },
  ];

  const donors = [
    { name: "UVU Partner Program", level: "Platinum" },
    { name: "BYU STEM Outreach", level: "Gold" },
    { name: "Community Arts Fund", level: "Silver" },
  ];

  res.render("index", {
    activePage: "home",
    user,
    stats,
    upcomingEvents,
    milestonesSummary,
    donors,
  });
});

// ----- LOGIN / LOGOUT (basically unused now, but safe to keep) -----

app.get("/login", (req, res) => {
  // since we auto-login, just redirect home
  return res.redirect("/");
});

app.post("/login", (req, res) => {
  // not really used in auto-admin mode
  return res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ----- ADMIN DASHBOARD -----
app.get("/admin/dashboard", requireAdmin, async (req, res) => {
  const user = req.session.user;

  // TODO: pull real KPIs from Surveys, Milestones, Participants, etc.
  const kpis = {
    avgSatisfaction: 4.6,
    avgUsefulness: 4.5,
    avgRecommend: 4.8,
    steamGradRate: "62%",
    steamJobRate: "55%",
  };

  const topEvents = [
    { name: "Summer STEAM Summit", score: 4.9, participants: 120 },
    { name: "Mariachi Workshop Series", score: 4.7, participants: 45 },
    { name: "Robotics & Coding Camp", score: 4.6, participants: 60 },
  ];

  const futureMilestones = [
    "Increase STEAM major rate to 70%",
    "Double post-college STEAM job placements",
    "Expand to X more schools",
  ];

  res.render("admin-dashboard", {
    activePage: "dashboard",
    user,
    kpis,
    topEvents,
    futureMilestones,
  });
});

// ----- PARTICIPANTS (view for all logged-in users; add for admins) -----
app.get("/participants", requireAuth, async (req, res) => {
  try {
    const participants = await knex("participants")
      .select(
        "participantid",
        "participantfirstname",
        "participantlastname",
        "participantemail",
        "participantrole",
        "participantcity",
        "participantstate"
      )
      .orderBy("participantlastname", "asc");

    res.render("participants-list", {
      activePage: "participants",
      user: req.session.user,
      participants,
    });
  } catch (err) {
    console.error("Error loading participants:", err);
    res.status(500).send("Error loading participants.");
  }
});

app.get("/participants/new", requireAdmin, (req, res) => {
  res.render("participants-new", {
    activePage: "participants",
    user: req.session.user,
    error: null,
  });
});

app.post("/participants/new", requireAdmin, async (req, res) => {
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
    });

    res.redirect("/participants");
  } catch (err) {
    console.error("Error creating participant:", err);
    res.render("participants-new", {
      activePage: "participants",
      user: req.session.user,
      error: "Error creating participant. Maybe email already exists?",
    });
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
    const donations = await knex("donations")
      .select(
        "donationid",
        "participantemail",
        "donationdate",
        "donationamount",
        "participantid"
      )
      .orderBy("donationdate", "desc")
      .limit(200);

    res.render("admin-donations", {
      activePage: "admin-donations",
      user: req.session.user,
      donations,
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

// ----- START SERVER -----
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log("The server is listening on port", port);
});
