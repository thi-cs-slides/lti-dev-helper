const express = require('express');
const session = require('express-session');
const debug = require('debug')('simple:index');
const lti = require('ims-lti');

// Default Config Values
const DEFAULT_SECRET = "97FA818F1F10";
const DEFAULT_KEY = "40030F4A";

// LTI Outcome: required to handle cached
const ltiOutcome = require('ims-lti/lib/extensions/outcomes');
const HMAC_SHA1 = require('ims-lti/lib/hmac-sha1');
function OutcomeRecreator(data) {
    Object.assign(this, data);
    this.signer = new HMAC_SHA1();
}
OutcomeRecreator.prototype = ltiOutcome.OutcomeService.prototype;

function sendOutcome(value, outcomeConfig, callback) {
    const outcome = new OutcomeRecreator(outcomeConfig);
    outcome.send_replace_result(value, callback);
}

function readOutcome(outcomeConfig, callback) {
    const outcome = new OutcomeRecreator(outcomeConfig);
    outcome.send_read_result(callback);
}

// Liquid for Templates
const { Liquid } = require('liquidjs')
const engine = new Liquid()

// Configuration handling
const ips = process.env.TRUSTED_IPS ? process.env.TRUSTED_IPS.split(',') : [];
const config = {
    port: process.env.PORT || 4000,
    secret: process.env.SECRET || DEFAULT_SECRET,
    trusted: (ip) => ips.length == 0 ? true : ips.indexOf(ip) != -1,
    cookie: {
        secure: process.env.COOKIE_SECURE || false,
        maxAge: process.env.COOKIE_MAX_AGE || 60 * 60 * 24 * 1000
    },
    lti: {
        secret: process.env.LTI_SECRET || DEFAULT_SECRET,
        key: process.env.LTI_SECRET || DEFAULT_KEY
    }
};

// Prepare Express App
const app = express();

const startApp = function() {
    // Check trusted ips
    app.engine('liquid', engine.express())
    app.set('views', './templates');
    app.set('view engine', 'liquid')
    app.set('trust proxy', config.trusted)

    // Handle JSON data
    app.use(express.json());
    app.use(express.urlencoded({extended: true}))

    // Config session storage
    app.use(session({
        secret: config.secret,
        resave: false,
        saveUninitialized: true,
        cookie: {
            secure: config.cookie.secure,
            maxAge: config.cookie.maxAge
        }
    }));

    // Config CORS for express
    app.use((req, res, next) => {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Methods", "OPTIONS, PUT, POST, DELETE, GET");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, X-Access-Token");
        res.header("Access-Control-Expose-Headers", "Content-Type, X-Access-Token");
        // Intercepts OPTIONS method
        if ("OPTIONS" === req.method) {
            res.sendStatus(200);
        } else {
            next();
        }
    });

    app.use('/version', (req, res) => res.send({version: require('./package.json').version}));

    app.post('/lti', (req, res, next) => {
        // Get Information from LTI-Payload
        const contextId = req.body.context_id;
        const consumerKey = req.body.oauth_consumer_key;
        const userId = req.body.user_id;
        debug(`Start auth for ${userId} with ${consumerKey} for ${contextId}`);

        // Validate Request
        const provider = new lti.Provider(consumerKey, config.lti.secret);
        // Validation requires req reference from express, this should have
        // matching informations like domain, port and scheme
        provider.valid_request(req, (err, isValid) => {
            if (isValid) {
                req.session.userId = userId;
                req.session.contextId = contextId;
                req.session.ltiPayload = JSON.stringify(req.body, undefined, 2);
                
                // A valid request generates an outcome service for direct
                // access, this can not be stored in a session!
                // Thus, storing only the data and recreate the service later.
                const outcomeData = provider.outcome_service;
                req.session.outcomeData = Buffer.from(JSON.stringify(outcomeData), 'utf-8').toString('base64');

                // Try to read last grading state
                readOutcome(outcomeData, (err, result) => {
                    if(err) {
                        debug(err);
                    } else {
                        debug(`Received existing outcome: ${result}`);
                    }
                    req.session.currentOutcome = result || 0;
                    res.redirect(301, '/');
                })
            } else {
                debug(`Error validating request for ${consumerKey}`, err);
                next(err);
            }
        });
    });

    app.get('/outcome/:value', (req, res, next) => {
        const value = Math.max(0.0, Math.min(1.0, parseFloat(req.params.value)));
        const outcomeData = req.session.outcomeData;
        if(!outcomeData) {
            res.status(403).send('Missing LTI Authentification.');
        }
        debug("Start updating grading to result " + value);
        const outcomeConfigFromPayloadText = Buffer.from(outcomeData, 'base64').toString('utf-8');
        sendOutcome(value, JSON.parse(outcomeConfigFromPayloadText), (err, result) => {
            if (err) {
                debug("Couldn't update result", err);
                res.status(500).send(err);
            } else {
                debug("Successfully updated outcome to " + value);
                res.status(204).send();
                req.session.currentOutcome = value;
            }
        });
    });
    app.get('/', (req, res, next) => {
        if(req.session.userId) {
            res.render('online', {
                key: config.lti.key,
                secret: config.lti.secret,
                userId: req.session.userId,
                contextId: req.session.contextId,
                ltiPayload: req.session.ltiPayload,
                currentOutcome: req.session.currentOutcome
            })
        } else {
            res.render('offline', {
                secret: config.lti.secret,
                key: config.lti.key
            })
        }
    });

    app.listen(config.port, function () {
        debug(`listening on ${config.port}`);
    });
};

startApp();

module.exports = app;