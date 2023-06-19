// openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
import dotenv from "dotenv";
dotenv.config();
import express from "express";
import https from "https";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import passport from "passport";
import { Strategy } from "passport-google-oauth20";
import helmet from "helmet";
import cookieSession from "cookie-session";

const app = express();
const port = process.env.PORT || '3000';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const certpath = path.join(__dirname, "./security/cert.pem");
const keypath = path.join(__dirname, "./security/key.pem");
app.use(helmet());
app.use(cookieSession({
    name:'session',
    keys: [process.env.KEY1, process.env.KEY2],
    maxAge: 60 * 60 * 1000
}))
app.use(passport.initialize());
app.use(passport.session());
// save session from cookie
passport.serializeUser((user, done) => {
    done(null, user.id);
});
// read session from cookie
passport.deserializeUser((id, done) => {
    done(null, id);
});
app.get("/", (req, res) => {
    res.status(200).sendFile(path.join(__dirname, "./public/google.html"))
});

// routes middleware to checked login or not
const islogined = (req,res,next)=>{
    console.log("  current user ", req.user)
 const login =req.isAuthenticated() &&req.user;
 if (!login){
    res.status(404).send("Invalid excesss");
 }
 next();
}
app.get("/login", islogined,(req, res) => {
    res.status(200).sendFile(path.join(__dirname, "./public/logout.html"));
});
app.get("/failure", (req, res) => {
    res.status(200).send("failure");
});
const auth_option = {
    authorizationURL: "https://accounts.google.com/o/oauth2/auth"
    ,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    tokenURL: "https://oauth2.googleapis.com/token",
    callbackURL: "/auth/google/callback",
}
const verifycallback = (accesstoken, refreshtoken, profile, done) => {
    console.log('profile', profile)
    done(null, profile);
}
passport.use(new Strategy(auth_option,
    verifycallback
));

app.get("/auth/google", passport.authenticate('google', {
    scope: ['email']
}), (req, res) => {
    console.log(" running  auth google")
});
app.get("/auth/google/callback", passport.authenticate('google', {
    failureRedirect: "/failure",
    successRedirect: "/login",
  session:true,
}), (req, res) => {
    console.log(" running  auth google callback")
});
app.get("/auth/google/signout", 
(req, res) => {
    req.logout(req.user, err => {
      if(err) return next(err);
    });
    return res.redirect("/");
  });
https.createServer({
    cert: fs.readFileSync(certpath),
    key: fs.readFileSync(keypath),
}, app).listen(port, () => {
    console.log(" Listening  at port:", port)
});
