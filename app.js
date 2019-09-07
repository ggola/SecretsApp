//jshint esversion:6
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
// google sign in strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate')
// facebook sign in strategy
const FacebookStrategy = require('passport-facebook').Strategy;

//**************************************************************
const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

// 1. Set up session
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));
// 2. Initialize passport on the app
app.use(passport.initialize());
// 3. Tell app to use passport to manage our session
app.use(passport.session());

// Using mongo db with localhost: 27017
mongoose.connect("mongodb://localhost:27017/secretsAppUsersDB", {useNewUrlParser:true});
mongoose.set('useCreateIndex', true);

// 4. Define user schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

// 5. Add passport local mongoose as a plugin to the schema
//    We use this to hash + salt passwords and to add users to DB
userSchema.plugin(passportLocalMongoose);
// find or create method for mongodb comes from a npm package
userSchema.plugin(findOrCreate);

// 6. Define user model
const User = new mongoose.model("User", userSchema);

// 7. Configure passport local auth strategy (email + password)
passport.use(User.createStrategy());

// 8. Add and remove session cookie for current user
//    serialize and deserialize for all types of authentication (local, Google, Facebook)
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// 9. Add Google and Facebook sign in strategis
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    // either find the user in our DB by google.id or we create it
    User.findOrCreate({ username: profile.id, googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Facebook sign in
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'emails', 'displayName']
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ username: profile.id, facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//**************************************************************
app.get("/", function(req, res){
  res.render('home');
});

// Google sign in page
app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile", "email"]}));

// Google redirect when the user has logged in
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

// Facebook sign in page
app.get("/auth/facebook",
  passport.authenticate("facebook", {scope: ["email"]}));

// Facebook redirect when the user has logged in
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render('login');
});

app.get("/register", function(req, res){
  res.render('register');
});

app.get("/secrets", function(req, res){
  // Verify that user is authenticated
  if (req.isAuthenticated()) {
    // Load all secrets
    User.find({secret: {$ne : null}}, function(err, foundUsers){
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          res.render("secrets", {usersWithSecrets: foundUsers});
        }
      }
    });
  } else {
    // Here the user is deserialized (cookie dismissed)
    res.redirect("/login");
  }
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    // Here the user is deserialized (cookie dismissed)
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;
  // Find current user in database - passport saves the user's details in the req parameter req.user
  const userId = req.user._id;
  User.findOne(userId, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(err){
          if (err) {
            console.log(err);
          } else {
            res.redirect("/secrets");
          }
        });
      }
    }
  });
});

app.post("/register", function(req, res){

  // Use passportLocalMongoose to register in mondodb
  User.register({username: req.body.username}, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      // NOTE: the following callback is called only if the registration was successful
      passport.authenticate("local")(req, res, function(){
        // Here the user is serialized (cookie sent to browser)
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res){

  const newUser = new User({
    username: req.body.username,
    password: req.body.password
  });
  // Use passport method login() on req.
  req.login(newUser, function(err){
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      // NOTE: the following callback is called only if the login was successful
      passport.authenticate("local")(req, res, function(){
        // Here the user is serialized (cookie sent to browser)
        res.redirect("/secrets");
      });
    }
  })

});

// NOTE: all cookies get deleted when the server is restarted
let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function() {
  console.log("Server started");
});
