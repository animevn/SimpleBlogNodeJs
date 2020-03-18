const functions = require("firebase-functions");
const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const admin = require("firebase-admin");
const firebase = require("firebase/app");
const {google} = require("googleapis");
require("firebase/auth");

const serviceAcountKey = require("./serviceAccountKey");
admin.initializeApp({
  credential:admin.credential.cert(serviceAcountKey),
  databaseURL:"https://flashchat-2020.firebaseio.com"
});
const db = admin.firestore();

const firebaseKey = require("./firebaseKey");
firebase.initializeApp(firebaseKey.firebaseConfig);
firebase.auth().setPersistence(firebase.auth.Auth.Persistence.NONE);

const googleApiKey = require("./googleApiKey");
const CLIENT_ID = googleApiKey.web.client_id;
const CLIENT_SECRET = googleApiKey.web.client_secret;
const REDIRECT_URL = googleApiKey.web.redirect_uris[0];
const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URL);

const app = express();
app.set("view engine", "ejs");
app.use(cookieParser());
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static("public"));

function setCookie(res, user, endpoint) {
  user.getIdToken().then(idToken=>{
    //cookie expires in one day
    const timeOut = 60 * 60 * 24 * 1000;
    admin.auth().verifyIdToken(idToken).then(result=>{
      //force user to re-signin after 60 minutes
      if (new Date().getTime()/1000 - result.auth_time < 60 * 60){
        return admin.auth().createSessionCookie(idToken, {expiresIn:timeOut})
      }
      throw new Error("Sign in again after 60 minutes");
    }).then(sessionCookie=>{
      const options = {maxAge:timeOut, httpOnly:true, secure:false};
      //cookie name must be named __session to use with firebase admin
      res.cookie("__session", sessionCookie, options);
      res.redirect(endpoint);
    }).catch(()=>res.status(401).send("UNAUTHORISED REQUEST"));
  })
}

async function isSignIn(req){
  const sessionCookie = req.cookies.__session || "";
  return await admin.auth().verifySessionCookie(sessionCookie, true)
  .then(()=>{return true;}).catch(()=>{return false;});
}

///////////////////////////
//Routing navigation parts

app.get("/", (req, res)=>{
  const posts = [];
  db.collectionGroup("blogs").get().then(snapshot=>{
    snapshot.forEach(doc=> posts.push(doc.data()));
  }).then(async ()=>{
    res.render("index", {homeActive:"active", aboutActive:"", contactActive:"",
    posts:posts, isSignIn: await isSignIn(req)});
  }).catch(err=>console.log(err));
});

app.get("/contact", async (req, res)=>{
  res.render("contact",
    {homeActive:"", aboutActive:"", contactActive:"active", isSignIn: await isSignIn(req)});
});

app.get("/about", async (req, res)=>{
  res.render("contact",
    {homeActive:"", aboutActive:"active", contactActive:"", isSignIn: await isSignIn(req)});
});

app.get("/login", async (req, res)=>{
  res.render("login",
    {homeActive:"", aboutActive:"", contactActive:"", isSignIn: await isSignIn(req)});
});

///////////////////////////
//auth parts

//google login
app.get("/google-auth", (req, res)=>{
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type:"offline",
    //userinfo.email and userinfo.profile are minimum needed to access user profile
    scope: ["https://www.googleapis.com/auth/userinfo.email",
      "https://www.googleapis.com/auth/userinfo.profile"]
  });
  res.redirect(authUrl);
});

//process redirects from google, /auth/google/callback is defined in google api credential, and
//can be changed to other name
app.get("/auth/google/callback", (req, res)=>{
  const code = req.query;
  if (code){
    oAuth2Client.getToken(code, (err, token)=>{
      if (err){
        console.log(err);
        res.redirect("/");
      }else {
        let credential = firebase.auth.GoogleAuthProvider.credential(token.id_token);
        firebase.auth().signInWithCredential(credential)
        .then(result=> setCookie(res, result.user, "/"))
        .catch(err=>{
          console.log(err);
          res.redirect("/");
        })
      }
    });
  }
});

//logout
app.get("/logout", (req, res)=>{
  const sessionCookie = req.cookies.__session || "";
  res.clearCookie("__session");
  if (sessionCookie){
    admin.auth().verifySessionCookie(sessionCookie, true).then(result=>{
      return admin.auth().revokeRefreshTokens(result.sub);
    }).then(()=> res.redirect("/")).catch(()=> res.redirect("/"));
  }else {
    res.redirect("/");
  }
});





















//routing all error 404 to homepage
app.get("**", (req, res)=>{
  res.status(404).redirect("/");
});

exports.app = functions.https.onRequest(app);





















