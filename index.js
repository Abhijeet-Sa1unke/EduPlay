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
   Passport Google Strategy
   ===================== */
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
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
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

/* =====================
   Passport Facebook Strategy
   ===================== */
passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "/auth/facebook/callback",
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
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

/* =====================
   Serialize & Deserialize
   ===================== */
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err, null);
  }
});

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
  failureFlash: true   // 👈 enables error messages
}));


// Google OAuth
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", {
  successRedirect: "/student_dashboard",
  failureRedirect: "/logincard_student"
}));

// Facebook OAuth
app.get("/auth/facebook", passport.authenticate("facebook"));
app.get("/auth/facebook/callback", passport.authenticate("facebook", {
  successRedirect: "/student_dashboard",
  failureRedirect: "/logincard_student"
}));

// Dashboard (protected)
app.get("/student_dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/logincard_student");
  res.render("student_dashboard.ejs", { user: req.user });
});

// Logout
app.get("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect("/");
  });
});



app.listen(port, () => console.log(`✅ Server running on http://localhost:${port}`));
