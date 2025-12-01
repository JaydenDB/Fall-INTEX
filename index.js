require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const multer = require("multer");

const app = express();

// ----- VIEW ENGINE -----
app.set("view engine", "ejs");
// (optional but good idea) ensure views folder
app.set("views", path.join(__dirname, "views"));

// ----- STATIC FILES -----
const uploadRoot = path.join(__dirname, "images");
const uploadDir = path.join(uploadRoot, "uploads");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, file.originalname),
});

const upload = multer({ storage });

// serve uploaded images (if you need later)
app.use("/images", express.static(uploadRoot));

// serve public/ (css, js, etc.)
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

// ----- DATABASE (not used yet, but set up) -----
const knex = require("knex")({
  client: "pg",
  connection: {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "postgres",
    password: process.env.DB_PASSWORD || "ChPost05$",
    database: process.env.DB_NAME || "foodisus",
    port: process.env.DB_PORT || 5432,
  },
});

// ----- ROUTES -----

// HOME / LANDING PAGE
app.get("/", (req, res) => {
  const user = null; // later: pull from req.session.user

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
        "A full-day summit that combines art, STEM, and college exploration.",
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

// ADMIN DASHBOARD
app.get("/admin/dashboard", (req, res) => {
  // temporary fake admin until auth is wired up
  const user = { name: "Admin User", role: "admin" };

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

// ----- START SERVER -----
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log("The server is listening on port", port);
});
