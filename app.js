//jshint esversion:6
require('dotenv').config();
// it's important to put it right at the top because otherwise if you try to use an environment variable and it's not configured(对计算机设备进行）配置 then you won't be able to access it.
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(bodyParser.urlencoded({
  extended: true
}));
app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose
  .connect(process.env.MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(console.log("Connected to MongoDB"))
  .catch((err) => console.log(err));

// this set is to solve a grammer problem
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  // facebookId: String,
  secret: String
});


// userSchema.plugin(encrypt, { secret:process.env.SECRET, encryptedFields: ['password'] });

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// it's from passport--done……
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-60h0.onrender.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

// passport.use(new FacebookStrategy({
//     clientID: process.env.FACEBOOK_APP_ID,
//     clientSecret: process.env.FACEBOOK_APP_SECRET,
//     callbackURL: "http://localhost:3000/auth/facebook/secrets"
//   },
//   function(accessToken, refreshToken, profile, cb) {
//     User.findOrCreate({
//       facebookId: profile.id
//     }, function(err, user) {
//       return cb(err, user);
//     });
//   }
// ));

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
// use passport to authenticate our user using the google strategy; what we want is the user's profile
  passport.authenticate("google", {
    scope: ["profile"]
  })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', {
    failureRedirect: "/login"
  }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

// app.get('/auth/facebook',
//   passport.authenticate('facebook'));
//
// app.get('/auth/facebook/secrets',
//   passport.authenticate('facebook', {
//     failureRedirect: '/login'
//   }),
//   function(req, res) {
//     // Successful authentication, redirect home.
//     res.redirect('/secrets');
//   });

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res){
  // 在这里,"secret" is a field, {$ne: null} means field not null
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        // the more secrets are submitted, the more will be shown up in the secret page.
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit",function(req,res) {
  const submittedSecret = req.body.secret;
  // console.log(req.user.id);

  User.findById(req.user.id, function(err,foundUser){
    if (err){
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
        // add in the secret into the database
      }
    }
  });
  // find the current user in our database and then save the secret into their file(passport saves the user details by using req.user)
});

// 属于passport的功能，Invoking logout() will clear the login session (if any).
app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res) {
// collection.register 是 passport-local-mongoose 的功能
  User.register({
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      // authenticate our user using passport; the type of authemtication we're performing is local
      //这一串authenticate都是passport的功能
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res) {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
// req.login 属于 passport 的功能，it can be used to establish a login session.
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 8000;
}
app.listen(port, function(){
  console.log("Server has started successfully.");
});
