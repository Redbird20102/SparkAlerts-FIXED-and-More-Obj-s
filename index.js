/*
NWWS-OI XMPP INGEST CLIENT FOR SPARKRADAR.APP

(c) 2024 Tyler Granzow - not to be used without permission


WARNING from the NWWS-OI system:
**WARNING**WARNING**WARNING**WARNING**WARNING**WARNING**WARNING**WARNING**

This code connects to a United States Federal Government computer system,
which may be accessed and used only for official Government business by
authorized personnel.  Unauthorized access or use of the computer system
may subject violators to criminal, civil, and/or administrative action.

All information on the computer system may be intercepted, recorded,
read, copied, and disclosed by and to authorized personnel for official
purposes, including criminal investigations. Access or use of the
computer system by any person whether authorized or unauthorized,
varITUTES CONSENT to these terms.

**WARNING**WARNING**WARNING**WARNING**WARNING**WARNING**WARNING**WARNING**

*/

// Access token for the API
// Load local .env if available (optional dependency)
try { require('dotenv').config(); } catch (e) { /* dotenv not installed; environment variables should be provided by the host */ }

// Access token for the API (prefer environment variable)
const VALID_ACCESS_TOKEN = process.env.VALID_ACCESS_TOKEN || 'p8GrcfYxhlfH3iFkpCXWgIVePrOnus2w';

var { match } = require('assert');
var { json } = require('stream/consumers');
const fs = require('node:fs');
const { log } = require('node:console');
const express = require('express');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const port = 8433;

// API Keys configuration with rate limits and metadata
// You can provide API keys as a JSON string in the environment variable `API_KEYS_JSON`.
// Example:
// API_KEYS_JSON='{"your_api_key_here":{"name":"Prod Key","rateLimit":100}}'
let API_KEYS = {};
if (process.env.API_KEYS_JSON) {
    try {
        API_KEYS = JSON.parse(process.env.API_KEYS_JSON);
    } catch (e) {
        console.warn('Failed to parse API_KEYS_JSON, falling back to default. Error:', e.message);
        API_KEYS = {};
    }
}

// Fallback to the single development token if nothing provided
if (!API_KEYS || Object.keys(API_KEYS).length === 0) {
    API_KEYS = {
        [VALID_ACCESS_TOKEN]: {
            name: 'Development API Key',
            rateLimit: 100, // requests per window
            whitelist: [], // allowed IPs/domains
            lastUsed: null,
            active: true
        }
    };
}

// Generate HMAC signature for request verification
function generateSignature(apiKey, timestamp, method, path) {
    const hmac = crypto.createHmac('sha256', apiKey);
    const data = `${timestamp}${method}${path}`;
    return hmac.update(data).digest('hex');
}

// CORS configuration
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, curl, etc)
        if (!origin) return callback(null, true);
        
        // Always allow sparkradar.app and its subdomains
        if (origin.includes('sparkradar.app')) {
            return callback(null, true);
        }
        
        // For other origins, we'll validate their API key and signature in the request handler
        callback(null, true);
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 204
};

// Setup middleware in correct order
app.use(cors(corsOptions));
app.use(express.json());

// Custom rate limiter based on API key and IP
const apiRateLimiter = rateLimit({
    windowMs: 15 * 60, // 15 seconds
    max: (req) => {
        const apiKey = req.get('Authorization')?.split(' ')[1];
        return apiKey && API_KEYS[apiKey] ? API_KEYS[apiKey].rateLimit : 30;
    },
    keyGenerator: (req) => {
        const apiKey = req.get('Authorization')?.split(' ')[1] || '';
        return `${apiKey}_${req.ip}`;
    },
    message: { 
        status: "ERROR", 
        message: "Rate limit exceeded. Please slow down your requests." 
    }
});

// Combined origin and token check middleware
const validateRequest = (req, res, next) => {
    const origin = req.get('origin') || req.get('referer') || '';
    const authHeader = req.get('Authorization');
    const timestamp = req.get('X-Request-Time');
    const signature = req.get('X-Signature');
    
    // Allow requests from sparkradar.app or its subdomains without additional auth
    if (origin && new URL(origin).hostname.endsWith('sparkradar.app')) {
        nosyncLog(`Authorized access from sparkradar.app domain: ${origin}`);
        return next();
    }

    // For non-sparkradar.app origins, require proper authentication
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        nosyncLog(`Missing or invalid Authorization header from: ${origin}`);
        return res.status(401).json({
            status: "ERROR",
            message: "Missing or invalid Authorization header"
        });
    }

    const apiKey = authHeader.split(' ')[1];
    const keyConfig = API_KEYS[apiKey];

    // Validate API key
    if (!keyConfig || !keyConfig.active) {
        nosyncLog(`Invalid or inactive API key from: ${origin}`);
        return res.status(401).json({
            status: "ERROR",
            message: "Invalid or inactive API key"
        });
    }

    // Validate timestamp (within 5 minutes)
    if (!timestamp || Math.abs(Date.now() - parseInt(timestamp)) > 300000) {
        nosyncLog(`Invalid or expired timestamp from: ${origin}`);
        return res.status(401).json({
            status: "ERROR",
            message: "Request timestamp invalid or expired"
        });
    }

    // Validate signature
    const expectedSignature = generateSignature(apiKey, timestamp, req.method, req.path);
    if (!signature || signature !== expectedSignature) {
        nosyncLog(`Invalid signature from: ${origin}`);
        return res.status(401).json({
            status: "ERROR",
            message: "Invalid request signature"
        });
    }

    // Update key usage metadata
    keyConfig.lastUsed = Date.now();
    
    // Request is authenticated
    nosyncLog(`Authorized access with valid API key from: ${origin}`);
    next();
};

// Apply middleware in correct order
app.use(express.json());
app.use(cors(corsOptions));
app.use(apiRateLimiter);  // Apply rate limiting
app.use(validateRequest);  // Apply request validation

// Log all requests
app.use((req, res, next) => {
    nosyncLog(`${req.method} ${req.path} from ${req.get('origin') || 'Unknown Origin'}`);
    next();
});

function nosyncLog(message) {
    // Convert to EST and format date
    const date = new Date();
    const estDate = new Date(date.toLocaleString('en-US', { timeZone: 'America/New_York' }));
    const formattedDate = estDate.toLocaleString('en-US', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });

    const logMessage = `[${formattedDate} EST] ${message}\n`;

    // Read existing logs
    try {
        const existingLogs = fs.existsSync('service.log') 
            ? fs.readFileSync('service.log', 'utf8')
            : '';

        // Split logs into lines and keep only the latest 999 lines
        let logLines = existingLogs.split('\n');
        if (logLines.length > 999) {
            logLines = logLines.slice(0, 999);
        }

        // Prepend new message and join lines back together
        fs.writeFileSync('service.log', logMessage + logLines.join('\n'));
    } catch (err) {
        console.error('Error writing to log file:', err);
        console.log('Original message:', message);
    }
}

// Health check endpoint - no rate limit or origin check for monitoring
// Randomized path for security through obscurity
app.get('/healthcheck8745425554458', (req, res, next) => {
    res.status(200).send({ status: "OK", timestamp: new Date().toISOString() });
});

// Main routes
app.get('/', (req, res) => {
    res.status(200).send({status: "OK"});
});

app.get('/alerts', async (req, res) => {
    try {
        const data = await fs.promises.readFile('alerts.json', 'utf8');
        const alerts = JSON.parse(data);

        res.status(200).send({ 
            status: "OK",
            count: alerts.length,
            alerts: alerts 
        });
    } catch (err) {
        console.error('Error handling alerts request:', err);
        nosyncLog(`Error serving alerts: ${err.message}`);
        res.status(500).send({ 
            status: "ERROR", 
            message: "Internal server error while retrieving alerts." 
        });
    }
});

// Error handlers
app.use((req, res, next) => {
    res.status(404).send({ 
        status: "ERROR", 
        message: "Endpoint not found" 
    });
});

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    nosyncLog(`Unhandled error: ${err.message}`);
    res.status(500).send({ 
        status: "ERROR", 
        message: "Internal server error" 
    });
});

app.listen(port, () => {
    console.log(`API is running on http://localhost:${port}`);
    nosyncLog(`API is running on http://localhost:${port}`);
});



(async () => {
    // Imports
    var wsModule = await import('ws');
    global.WebSocket = wsModule.default || wsModule.WebSocket || wsModule;

    var xml2js = require('xml2js');
    var { client, xml } = await import('@xmpp/client');
    var player = require('play-sound')(); // DEBUG
    var fs = require('fs');
    var path = require('path');

    async function log(message) {
        // Convert to EST and format date
        const date = new Date();
        const estDate = new Date(date.toLocaleString('en-US', { timeZone: 'America/New_York' }));
        const formattedDate = estDate.toLocaleString('en-US', {
            day: '2-digit',
            month: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });

        const logMessage = `[${formattedDate} EST] ${message}\n`;

        // Read existing logs
        try {
            const existingLogs = fs.existsSync('service.log') 
                ? fs.readFileSync('service.log', 'utf8')
                : '';

            // Split logs into lines and keep only the latest 999 lines
            let logLines = existingLogs.split('\n');
            if (logLines.length > 999) {
                logLines = logLines.slice(0, 999);
            }

            // Prepend new message and join lines back together
            fs.writeFileSync('service.log', logMessage + logLines.join('\n'));
        } catch (err) {
            console.error('Error writing to log file:', err);
            console.log('Original message:', message);
        }
    }

    // Function to clean up the database
    async function periodicTask() {
        try {
            // Read in the database
            const data = JSON.parse(fs.readFileSync('alerts.json', 'utf8'));

            // If the alert is expired, remove it
            for (let alert of data) {
                let expiry = new Date(alert.expiry);
                let now = new Date();
                if (now > expiry) {
                    console.log(`Alert expired: ${alert.alertName}, removing from database.`);
                    data.splice(data.indexOf(alert), 1);
                }
            }

            // Write the cleaned database back to file
            fs.writeFile('alerts.json', JSON.stringify(data, null, 2), (err) => {});
        } catch (err) {
            log('Error in database cleanup:', err);
        }
    }

    // Variable to store the interval ID so we can stop it if needed
    let periodicTaskInterval = null;

    // Connection management
    let reconnectAttempt = 0;
    const MAX_RECONNECT_ATTEMPTS = 10;
    const INITIAL_RECONNECT_DELAY = 2000; // 2 seconds
    
    function createXMPPClient() {
        // Read XMPP configuration from environment variables to avoid hard-coding credentials.
        const xmppConfig = {
            service: process.env.XMPP_SERVICE || 'xmpp://nwws-oi.weather.gov',
            domain: process.env.XMPP_DOMAIN || 'nwws-oi.weather.gov',
            username: process.env.XMPP_USERNAME || null,
            password: process.env.XMPP_PASSWORD || null,
            resource: process.env.XMPP_RESOURCE || 'SparkRadar NWWS Ingest API (sparkradar.app)'
        };

        if (!xmppConfig.username || !xmppConfig.password) {
            console.warn('XMPP credentials not provided via environment variables. Skipping XMPP client creation.');
            return null;
        }

        const xmpp = client(xmppConfig);

        // Handle disconnections and errors
        xmpp.on('disconnect', () => {
            log('XMPP client disconnected. Will attempt reconnect...');
            handleReconnect();
        });

        xmpp.on('close', () => {
            log('XMPP connection closed. Will attempt reconnect...');
            handleReconnect();
        });

        return xmpp;
    }

    async function handleReconnect() {
        // Clear any existing intervals
        if (periodicTaskInterval) {
            clearInterval(periodicTaskInterval);
            periodicTaskInterval = null;
        }

        if (reconnectAttempt >= MAX_RECONNECT_ATTEMPTS) {
            log('Max reconnection attempts reached. Exiting...');
            process.exit(1);
        }

        // Exponential backoff with jitter
        const delay = INITIAL_RECONNECT_DELAY * Math.pow(2, reconnectAttempt) 
                     + Math.random() * 1000; // Add up to 1 second of random jitter
        
        log(`Attempting reconnection in ${Math.round(delay/1000)} seconds (attempt ${reconnectAttempt + 1}/${MAX_RECONNECT_ATTEMPTS})...`);
        
        await new Promise(resolve => setTimeout(resolve, delay));
        
        reconnectAttempt++;
        
        try {
            // Create new client instance
            xmpp = createXMPPClient();
            await xmpp.start();
        } catch (err) {
            log(`Reconnection attempt failed: ${err.message}`);
            handleReconnect();
        }
    }

    // Create initial XMPP client
    var xmpp = createXMPPClient();

    // Event listener for online event
    xmpp.on('online', (address) => {
        // Reset reconnection counter on successful connection
        reconnectAttempt = 0;
        
        log(`Connected to XMPP server as ${address}`);
        console.log('Connected to XMPP server');
        
        // Start the periodic task when we're online
        if (!periodicTaskInterval) {
            // Run once immediately
            periodicTask();
            // Then every 60 seconds
            periodicTaskInterval = setInterval(periodicTask, 60000);
        }

        // Join the NWWS chat room
        try {
            xmpp.send(
                xml('presence', {
                    to: 'nwws@conference.nwws-oi.weather.gov/SparkRadar',
                })
            );
        } catch (err) {
            log(`Error joining NWWS chat room: ${err.message}`);
            handleReconnect();
        }
    });

    // Event listener for incoming stanzas (messages)
    xmpp.on('stanza', (stanza) => {

        // Ignore non-message stanzas
        if (!stanza.is('message')) { return; }
        if (stanza.toString().includes("**WARNING**WARNING**WARNING**WARNING")) { return; }

        // Turn the XML to JSON because I hate XML
        var xml = stanza.toString();
        var parser = new xml2js.Parser();

        // From https://forecast.weather.gov/product_types.php?site=NWS
        var whitelist = [
            'TOR', // Tornado Warning                  TODO
            'SVR', // Severe Thunderstorm Warning        DONE
            'FFW', // Flash Flood Warning              TODO
            'SPS', // Severe Weather Statement           DONE
            'TSU', // Tsunami Alert                    TODO
            'FLW', // Flood Warning                      DONE
            'FRW', // Fire Warning                     TODO
            'SMW', // Special Marine Warning             DONE
            'SQW', // Snow Squall Warning              TODO
            'AVA', // Avalanche Watch                  TODO
            'AVW', // Avalanche Warning                TODO
            'EWW'  // Extreme Wind Warning             TODO
        ];

        var names = [
            'Tornado Warning',
            'Severe Thunderstorm Warning',
            'Flash Flood Warning',
            'Flood Watch', 
            'Severe Weather Statement',
            'Tsunami Alert', 
            'Flood Warning', 
            'Fire Warning', 
            'Special Marine Warning',
            'Snow Squall Warning',
            'Avalanche Watch', 
            'Avalanche Warning', 
            'Extreme Wind Warning'  
        ];

        parser.parseString(xml, (err, result) => {
            if (err) {
                console.warn('Error parsing XML, message will not be processed:', err);
                return;
            }

            // Safely extract the <body> text (common XMPP message structure)
            if (!result || !result.message || !result.message.body || !Array.isArray(result.message.body)) {
                console.warn('Invalid XML message structure:', result);
                return;
            }

            var body = result.message.body[0];
            if (body === undefined || body === null) {
                console.warn('Empty message body');
                return;
            }

            var headline = String(body);

            // Check if the headline contains any of the whitelist tokens
            var upperHeadline = String(headline);
            var matchIndex = whitelist.findIndex(token => upperHeadline.includes(token));
            var matches = matchIndex !== -1;
            var matchedToken = matches ? whitelist[matchIndex] : null;
            var matchedName = matches ? names[matchIndex] : null;

            if (!matches) return;

            log('Processing alert message:', headline);

            // Processing
            body = result;
            var rawText = body.message.x[0]._;

            // Extract alert name
            var alertNameMatch = rawText.match(/BULLETIN.*?\s+(.*?)\s+National Weather Service/);
            var alertName = alertNameMatch ? alertNameMatch[1].trim() : null;

            // Extract issuance office
            var issuanceOffice = body.message.x[0].$.cccc;

            // Extract issue time
            var issueTime = body.message.x[0].$.issue;

            // Extract lat/lon coordinates
            var latLonMatch = rawText.match(/LAT\.\.\.LON\s+([\d\s]+)/);
            let coordinates = [];
            if (latLonMatch) {
            var nums = latLonMatch[1].trim().split(/\s+/);
            for (let i = 0; i < nums.length; i += 2) {
                coordinates.push({
                lat: parseFloat(nums[i].slice(0, 2) + '.' + nums[i].slice(2)),
                lon: -parseFloat(nums[i + 1].slice(0, 2) + '.' + nums[i + 1].slice(2)) // Assuming western hemisphere
                });
            }
            }

            // Normalize coordinates to [[lat, lon], ...]
            var standardCoordinates = [];
            if (Array.isArray(coordinates)) {
                standardCoordinates = coordinates
                    .map(item => {
                        // handle already-array form [lat, lon]
                        if (Array.isArray(item) && item.length >= 2) {
                            return [Number(item[0]), Number(item[1])];
                        }
                        // handle object form {lat, lon}
                        if (item && typeof item === 'object' && 'lat' in item && 'lon' in item) {
                            return [Number(item.lat), Number(item.lon)];
                        }
                        return null;
                    })
                    .filter(pair => pair && isFinite(pair[0]) && isFinite(pair[1]));
            }
            // Replace original coordinates with standardized form
            coordinates = standardCoordinates;

            var vtecRegex = /\/O\..*?\/\n?/;
            var vtecMatch = rawText.match(vtecRegex);
            var expiry;

            if (vtecMatch) {
            var vtec = vtecMatch[0];
            var timeRangeRegex = /(\d{6}T\d{4}Z)-(\d{6}T\d{4}Z)/;
            var timeMatch = vtec.match(timeRangeRegex);

            if (timeMatch) {
                var expirationRaw = timeMatch[2]; // e.g., "251102T0315Z"
                var year = 2000 + parseInt(expirationRaw.slice(0, 2), 10);
                var month = parseInt(expirationRaw.slice(2, 4), 10) - 1; // JS months are 0-based
                var day = parseInt(expirationRaw.slice(4, 6), 10);
                var hour = parseInt(expirationRaw.slice(7, 9), 10);
                var minute = parseInt(expirationRaw.slice(9, 11), 10);

                var expirationDate = new Date(Date.UTC(year, month, day, hour, minute));
                expiry = expirationDate.toISOString();
            } else {
                log("Expiration time not found in VTEC string.");
            }
            } else {
                log("VTEC string not found in the alert.");
                vtecMatch = null;
            }

            // Format VTEC if it exists
            const formattedVtec = vtecMatch ? vtecMatch[0].replace(/\n/g, '') : null;

            // Output parsed result
            var parsedAlert = {
                matchedToken,
                matchedName,
                issuanceOffice,
                issueTime,
                coordinates,
                rawText,
                vtecMatch: formattedVtec,
                expiry
            };

            // Append the alert to alerts.json
            try {
                let alertsData = fs.readFileSync('alerts.json', 'utf8');
                let alerts = JSON.parse(alertsData);
                alerts.push(parsedAlert);
                fs.writeFileSync('alerts.json', JSON.stringify(alerts, null, 2));
            } catch (err) {
                console.error('Error updating alerts.json:', err);
                log('Error updating alerts.json:', err);
            }

            

            // Create the alerts directory if it doesn't exist
            var alertsDir = path.join(__dirname, 'alerts');
            if (!fs.existsSync(alertsDir)) {
                fs.mkdirSync(alertsDir);
            }

            // Create a new file with a timestamp and a safe headline/name
            var timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            // Fallbacks for alertName and headline if not present
            var safeAlertName = (typeof alertName === 'string' && alertName.length) ? alertName : (headline || 'unparsed-alert');
            // Sanitize filename to remove problematic characters
            var safeName = safeAlertName.replace(/[^a-z0-9-_\. ]/gi, '_').trim();
            var fileName = `${timestamp}_${safeName}.json`;
            var filePath = path.join(alertsDir, fileName);

            // Build a safe object to write (use parsed alert if available, otherwise include raw result)
            var alertToSave = {
                alertName: safeAlertName,
                headline: headline || null,
                parsed: (typeof parsedAlert !== 'undefined') ? parsedAlert : null,
                raw: result
            };

            // Write the parsed alert data to the file
            fs.writeFile(filePath, JSON.stringify(alertToSave, null, 2), (err) => {
                if (err) {
                    console.error('Error writing alert data to file:', err);
                    log('Error writing alert data to file:', err);
                } else {
                    console.log(`Alert data saved to ${filePath}`);
                    log(`Alert data saved to ${filePath}`);
                }
            });
        });

    });

    // Event listener for errors
    xmpp.on('error', (err) => {
        console.error('XMPP error:', err);
        log('XMPP error: ' + err.toString());
        // Clean up interval on error
        if (periodicTaskInterval) {
            clearInterval(periodicTaskInterval);
            periodicTaskInterval = null;
        }
    });

    // Clean up interval when offline
    xmpp.on('offline', () => {
        log("Connection offline")
        console.log('XMPP connection offline');
        if (periodicTaskInterval) {
            clearInterval(periodicTaskInterval);
            periodicTaskInterval = null;
        }
    });

    // Start the connection
    try {
        await xmpp.start();
    } catch (err) {
        console.error('\nFailed to start XMPP client:', err);
        log('Failed to start XMPP client:' + err);
        process.exit(1);
    }
})().catch(err => {
    console.error('\nAn error occurred:', err);
    log('An error occurred: ' + err);
    console.log('Restarting in 5 seconds...');
    setTimeout(() => {}, 5000);
});