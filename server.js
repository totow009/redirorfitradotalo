require('dotenv').config(); // Load environment variables from .env
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const express = require('express');
const app = express();
const PORT = process.env.PORT || 4050;


// Configuration from .env
const TARGET_COUNTRY = process.env.COUNTRY; // Target country code
const TARGET_URL = process.env.TARGET; // URL for allowed users
const FALLBACK_URL = process.env.FALLBACK; // URL for denied users

// In-memory storage
let visits = [];
let stats = {
    allowed: 0,
    denied: 0,
    bots: 0,
    reasons: {
        vpn: 0,
        proxy: 0,
        bot: 0,
        country: 0
    },
   
    os: {
        windows: 0,
        macos: 0,
        linux: 0,
        android: 0,
        ios: 0,
        other: 0
    }
};

// Enhanced bot detection
const isBot = (userAgent) => {
    const bots = [
        /bot/, /crawler/, /spider/, /curl/, /wget/, /headless/, 
        /python-requests/, /phantomjs/, /cheerio/, /scrapy/, /zgrab/,
        /googlebot/, /bingbot/, /slurp/, /duckduckbot/, /baiduspider/,
        /yandexbot/, /sogou/, /exabot/, /facebot/, /ia_archiver/
    ];
    return bots.some(pattern => pattern.test(userAgent.toLowerCase()));
};

// OS detection
const detectOS = (userAgent) => {
    if (/windows/i.test(userAgent)) return 'Windows';
    if (/macintosh|mac os x/i.test(userAgent)) return 'MacOS';
    if (/linux/i.test(userAgent)) return 'Linux';
    if (/android/i.test(userAgent)) return 'Android';
    if (/iphone|ipad|ipod/i.test(userAgent)) return 'iOS';
    return 'Other';
};

// Middleware and configuration
app.set('view engine', 'ejs');
app.use(express.static('public'));

// Routes

app.get('/', async (req, res) => {

    res.send("hello world!");
})



app.get('/redirect', async (req, res) => {
    try {
        const ip = req.headers['x-forwarded-for'] || req.ip;
        const userAgent = req.headers['user-agent'] || '';
        
        // Get security data
        const geoResponse = await fetch(`http://ip-api.com/json/${ip}?fields=66842623`);
        const geoData = await geoResponse.json();
        
        // Threat detection
        const threats = {
            isBot: isBot(userAgent),
            isProxy: geoData.proxy || geoData.hosting,
            isVpn: geoData.vpn,
            wrongCountry: !TARGET_COUNTRY.includes(geoData.countryCode)
        };

        // Determine redirect
        const isThreat = Object.values(threats).some(v => v);
        const redirectUrl = isThreat ? FALLBACK_URL : TARGET_URL;

        // Detect OS
        const os = detectOS(userAgent);

        // Store visit
        const visitData = {
            ip,
            country: geoData.country,
            city: geoData.city || 'Unknown',
            flag: `https://flagcdn.com/48x36/${geoData.countryCode?.toLowerCase()}.png`,
            os, // Add OS information
            userAgent,
            timestamp: new Date(),
            status: isThreat ? 'Denied' : 'Allowed',
            reasons: Object.keys(threats).filter(k => threats[k]),
            isBot: threats.isBot,
            isProxy: threats.isProxy,
            isVpn: threats.isVpn
        };

        visits.push(visitData);
        stats[isThreat ? 'denied' : 'allowed']++;
        if (threats.isBot) stats.bots++;
        visitData.reasons.forEach(reason => stats.reasons[reason]++);
        stats.os[os.toLowerCase()]++;

        res.redirect(redirectUrl);

    } catch (error) {
        console.error('Error:', error);
        res.redirect(FALLBACK_URL);
    }
});

// Clear stats endpoint
app.post('/clear-stats', (req, res) => {
    visits = [];
    stats = {
        allowed: 0,
        denied: 0,
        bots: 0,
        reasons: {
            vpn: 0,
            proxy: 0,
            bot: 0,
            country: 0
        },
       
        os: {
            windows: 0,
            macos: 0,
            linux: 0,
            android: 0,
            ios: 0,
            other: 0
        }
    };
    res.redirect('/dashboard');
});

// Dashboard route
app.get('/dashboard', (req, res) => {
    res.render('dashboard', { visits, stats });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));