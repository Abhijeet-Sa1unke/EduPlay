import dotenv from "dotenv";
dotenv.config();

import express from "express";
import session from "express-session";
import passport from "passport";
import bcrypt from "bcrypt";
console.log("DB_PASS:", process.env.DB_PASS, "| Type:", typeof process.env.DB_PASS);

import pool from "./db.js";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import flash from "connect-flash";


const app = express();
const port = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

// Session
app.use(session({
  secret: process.env.SESSION_SECRET || "supersecret",
  resave: false,
  saveUninitialized: false
}));

// flash setup
app.use(flash());

// make flash vars available to all views
app.use((req, res, next) => {
  res.locals.error = req.flash("error");
  res.locals.success = req.flash("success");

  // Separate flashes for teachers
  res.locals.teacherError = req.flash("teacherError");
  res.locals.teacherSuccess = req.flash("teacherSuccess");

  next();
});


app.use(passport.initialize());
app.use(passport.session());

/* =====================
   Passport Local Strategy
   ===================== */
passport.use(new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0) return done(null, false, { message: "No user found" });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false, { message: "Incorrect password" });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));


/* =====================
   Google OAuth - Student
   ===================== */
passport.use("google-student", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/student/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE google_id=$1", [profile.id]);
    let user = result.rows[0];

    if (!user) {
      const insert = await pool.query(
        "INSERT INTO users (name, email, google_id) VALUES ($1,$2,$3) RETURNING *",
        [profile.displayName, profile.emails[0].value, profile.id]
      );
      user = insert.rows[0];
    }
    return done(null, { ...user, role: "student" });
  } catch (err) {
    return done(err);
  }
}));

/* =====================
   Google OAuth - Teacher
   ===================== */
passport.use("google-teacher", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/teacher/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails ? profile.emails[0].value : null;

    // 1. Try to find teacher by google_id
    let result = await pool.query("SELECT * FROM teachers WHERE google_id=$1", [profile.id]);
    let teacher = result.rows[0];

    // 2. If not found, try by email
    if (!teacher && email) {
      result = await pool.query("SELECT * FROM teachers WHERE email=$1", [email]);
      teacher = result.rows[0];

      // If found by email, just update google_id
      if (teacher) {
        await pool.query("UPDATE teachers SET google_id=$1 WHERE id=$2", [profile.id, teacher.id]);
        teacher.google_id = profile.id;
      }
    }

    // 3. If still not found, insert new
    if (!teacher) {
      const insert = await pool.query(
        "INSERT INTO teachers (name, email, google_id) VALUES ($1,$2,$3) RETURNING *",
        [profile.displayName, email, profile.id]
      );
      teacher = insert.rows[0];
    }

    return done(null, { ...teacher, role: "teacher" });
  } catch (err) {
    return done(err);
  }
}));




/* =====================
   Facebook OAuth - Student
   ===================== */
passport.use("facebook-student", new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "/auth/facebook/student/callback",
  profileFields: ["id", "displayName", "emails"]
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE facebook_id=$1", [profile.id]);
    let user = result.rows[0];

    if (!user) {
      const email = profile.emails ? profile.emails[0].value : null;
      const insert = await pool.query(
        "INSERT INTO users (name, email, facebook_id) VALUES ($1,$2,$3) RETURNING *",
        [profile.displayName, email, profile.id]
      );
      user = insert.rows[0];
    }
    return done(null, { ...user, role: "student" });
  } catch (err) {
    return done(err);
  }
}));

/* =====================
   Facebook OAuth - Teacher
   ===================== */
passport.use("facebook-teacher", new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "/auth/facebook/teacher/callback",
  profileFields: ["id", "displayName", "emails"]
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const result = await pool.query("SELECT * FROM teachers WHERE facebook_id=$1", [profile.id]);
    let teacher = result.rows[0];

    if (!teacher) {
      const email = profile.emails ? profile.emails[0].value : null;
      const insert = await pool.query(
        "INSERT INTO teachers (name, email, facebook_id) VALUES ($1,$2,$3) RETURNING *",
        [profile.displayName, email, profile.id]
      );
      teacher = insert.rows[0];
    }
    return done(null, { ...teacher, role: "teacher" });
  } catch (err) {
    return done(err);
  }
}));


/* =====================
   Serialize & Deserialize
   ===================== */
passport.serializeUser((user, done) => {
  // Save both id and role in session
  done(null, { id: user.id, role: user.role || "student" });
});

passport.deserializeUser(async (obj, done) => {
  try {
    let result;

    if (obj.role === "teacher") {
      result = await pool.query("SELECT * FROM teachers WHERE id=$1", [obj.id]);
      if (result.rows.length > 0) {
        return done(null, { ...result.rows[0], role: "teacher" });
      }
    } else {
      result = await pool.query("SELECT * FROM users WHERE id=$1", [obj.id]);
      if (result.rows.length > 0) {
        return done(null, { ...result.rows[0], role: "student" });
      }
    }

    return done(null, false);
  } catch (err) {
    return done(err, null);
  }
});


passport.use("teacher-local", new LocalStrategy(
  { usernameField: "email", passwordField: "password" },
  async (email, password, done) => {
    try {
      const result = await pool.query("SELECT * FROM teachers WHERE email=$1", [email]);
      if (result.rows.length === 0) return done(null, false, { message: "No teacher found" });

      const teacher = result.rows[0];
      const isMatch = await bcrypt.compare(password, teacher.password);
      if (!isMatch) return done(null, false, { message: "Incorrect password" });

      return done(null, { ...teacher, role: "teacher" }); // ✅ role added
    } catch (err) {
      return done(err);
    }
  }
));

/* =====================
   Routes
   ===================== */

// Home
app.get("/", (req, res) => {
  res.render("index.ejs", { user: req.user });
});

// Student login page
app.get("/logincard_student", (req, res) => {
  res.render("studentLogin.ejs");
});

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).send("All fields are required");
    }

    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashed]
    );

    console.log("User created:", result.rows[0]);
    res.redirect("/logincard_student"); // or send success response
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).send("Signup failed: " + err.message);
  }
});


// Local login
app.post("/login", passport.authenticate("local", {
  successRedirect: "/student_dashboard",
  failureRedirect: "/logincard_student",
  failureFlash: { type: "error", message: "Invalid email or password" } 
}));



// Google
app.get("/auth/google/student", passport.authenticate("google-student", { scope: ["profile", "email"] }));
app.get("/auth/google/student/callback", passport.authenticate("google-student", {
  successRedirect: "/student_dashboard",
  failureRedirect: "/logincard_student",
  failureFlash: { type: "error", message: "Google login failed" }
}));

// Facebook
app.get("/auth/facebook/student", passport.authenticate("facebook-student"));
app.get("/auth/facebook/student/callback", passport.authenticate("facebook-student", {
  successRedirect: "/student_dashboard",
  failureRedirect: "/logincard_student",
  failureFlash: { type: "error", message: "Facebook login failed" }
}));

// Google
app.get("/auth/google/teacher", passport.authenticate("google-teacher", { scope: ["profile", "email"] }));
app.get("/auth/google/teacher/callback", passport.authenticate("google-teacher", {
  successRedirect: "/teacher_dashboard",
  failureRedirect: "/logincard_teacher",
  failureFlash: { type: "teacherError", message: "Google login failed" }
}));

// Facebook
app.get("/auth/facebook/teacher", passport.authenticate("facebook-teacher"));
app.get("/auth/facebook/teacher/callback", passport.authenticate("facebook-teacher", {
  successRedirect: "/teacher_dashboard",
  failureRedirect: "/logincard_teacher",
  failureFlash: { type: "teacherError", message: "Facebook login failed" }
}));


// Dashboard (protected)
app.get("/student_dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/logincard_student");
  res.render("stud_dashboard.ejs", { user: req.user });
});

// Logout
app.get("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect("/");
  });
});

// Teacher login page
app.get("/logincard_teacher", (req, res) => {
  res.render("teacherLogin.ejs");
});

// Teacher signup
app.post("/teacher/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).send("All fields are required");
    }

    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO teachers (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashed]
    );

    console.log("Teacher created:", result.rows[0]);
    res.redirect("/logincard_teacher"); 
  } catch (err) {
    console.error("Teacher Signup Error:", err);
    res.status(500).send("Signup failed: " + err.message);
  }
});

// Teacher login
app.post("/teacher/login", passport.authenticate("teacher-local", {
  successRedirect: "/teacher_dashboard",
  failureRedirect: "/logincard_teacher",
  failureFlash: { type: "teacherError", message: "Invalid email or password" }
}));


// Teacher Dashboard (protected)
app.get("/teacher_dashboard", (req, res) => {
  if (!req.isAuthenticated() || req.user.role !== "teacher") {
    return res.redirect("/logincard_teacher");
  }
  res.render("teacher_dashboard.ejs", { teacher: req.user });
});




app.listen(port, () => console.log(`✅ Server running on http://localhost:${port}`));
