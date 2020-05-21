const fs = require('fs');
const express = require("express");
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const session = require('express-session');
const passport = require('passport');
const saml = require('passport-saml');

dotenv.config();

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

const samlStrategy = new saml.Strategy({
    // Service Provider's Login URL (ACS URL) that'll get the SAML response from IdP.
    callbackUrl: process.env.CALLBACK_URL,
    // Identity Provider's Single Sign on URL (HTTP-Redirect Binding)
    entryPoint: process.env.ENTRYPOINT,
    // Service Provider's Entity ID
    issuer: process.env.ISSUER,
    // Service Provider's Private Encryption Key
    decryptionPvk: fs.readFileSync(__dirname + '/cert/decryption_key.pem', 'utf8'),
    // Service Provider's Private Signing Key
    privateCert: fs.readFileSync(__dirname + '/cert/signing_key.pem', 'utf8'),
    // Identity Provider's Signing Certificate in a single line
    cert: "MIIDHDCCAgSgAwIBAgIVAMXVGogsmqnkwPUYCdxTPbev9l3ZMA0GCSqGSIb3DQEB BQUAMBcxFTATBgNVBAMTDGlkcC51c2Fzay5jYTAeFw0xMDEwMjUyMDU2NTBaFw0z MDEwMjUyMDU2NTBaMBcxFTATBgNVBAMTDGlkcC51c2Fzay5jYTCCASIwDQYJKoZI hvcNAQEBBQADggEPADCCAQoCggEBALMSOFuhTJKiB3amc9licNeAGA3vbw/qksAZ I90sBiS5F6fmRcqeO4yZRvNqmCPp/By1iTJOf0ryd50P7szRXSBPiwgnCTox4m5k TyBciLbqIj4rtLu9ThuADreCV225cilhwwFIPW93ksJYn2gIuPlBV3zNqT27pQIo NhVhFNy/RHRKctAWIaH66RForxVkofJ2f3sY3RfEpl7PjZSj35RJaiICNDBcL/9P miYmecit+pl8F64qmMZSr36Lond54RthIey3ai4Q5WMPKgkB/A0kk9hJN366GX/X JclXGMKimP4ymqmsyVIGUcu+8vBFHTsNu8Y8Sf/PSExfFzufus8CAwEAAaNfMF0w PAYDVR0RBDUwM4IMaWRwLnVzYXNrLmNhhiNodHRwczovL2lkcC51c2Fzay5jYS9p ZHAvc2hpYmJvbGV0aDAdBgNVHQ4EFgQUES778RCyfLDRWvsQSEz4R0JUHUwwDQYJ KoZIhvcNAQEFBQADggEBAHs1pJu8e1vHei30xNOnsO+RMx9Ye4AMR9dBmh2QkV5Q 7UzS1YlA2wr4x3YSnm4IPfOjrQW0brXZjytZWdU9EBfinn4OUUG5RMD/1d/Nu5Zu kDm+qt2mCaYoxhdinuUcb6aiJBucpxulZLzByGxTAHXqXqOlh6Y5cJUwlweFHLka D0NZ6TrcXo/7QHXhypSrNOAyXrN+ngQ8j6KJXmtjXj601I71upEVWOGaor172aNo 4OJ1yrQ6k4U6yjjuwrQEAjDCL3WYhrhGCwuu/l/AVw28RWHK5qKgMovdwIeukJfL B9WRkjxzB4gF0SyVYl64MQB5UICwuA6q6WLxlmMyWIY=",
    // NameID format used by Identity Provider
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    disableRequestedAuthnContext: true

}, function(profile, done) {
    return done(null, profile);
});

passport.use(samlStrategy);

const app = express();

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated())
        return next();
    else
        return res.redirect('/login');
}

app.get('/login',
    passport.authenticate('saml', { failureRedirect: '/login/fail' }),
    function (req, res) {
        res.redirect('/');
    }
);

app.get('/',
    ensureAuthenticated,
    function(req, res) {
        res.send('Authenticated');
    }
);

app.post('/login/callback',
    passport.authenticate('saml', { failureRedirect: '/login/fail' }),
    function(req, res) {
        res.redirect('/');
    }
);

app.get('/login/fail',
    function(req, res) {
        res.status(401).send('Login failed');
    }
);

app.get('/shibboleth/metadata',
    function(req, res) {
        res.type('application/xml');
        res.status(200).send(samlStrategy.generateServiceProviderMetadata(
            fs.readFileSync(__dirname + '/cert/decryption_cert.pem', 'utf8'),
            fs.readFileSync(__dirname + '/cert/signing_cert.pem', 'utf8')
        ));
    }
);

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
});

//general error handler
app.use(function(err, req, res, next) {
    console.log("Fatal error: " + JSON.stringify(err));
    next(err);
});

const server = app.listen(3000, function () {
    console.log('Listening on port %d', server.address().port)
});
