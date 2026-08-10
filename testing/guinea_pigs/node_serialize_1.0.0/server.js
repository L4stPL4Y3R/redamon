/**
 * Guinea Pig - Node.js Test Server
 *
 * FOR AUTHORIZED TESTING ONLY
 */

var express = require('express');
var cookieParser = require('cookie-parser');
var serialize = require('node-serialize');
var path = require('path');

var app = express();
var PORT = 3000;

app.use(cookieParser());

// Serve static files (landing page, health check)
app.use(express.static(path.join(__dirname, 'www')));

// Health check endpoint
app.get('/health', function(req, res) {
    res.type('text/plain').send('OK');
});

// Status endpoint (similar to CGI status in Apache guinea pigs)
app.get('/status', function(req, res) {
    var os = require('os');
    res.type('text/html').send(
        '<!DOCTYPE html>' +
        '<html><head><title>System Status</title>' +
        '<style>' +
        'body { font-family: monospace; background: #1a1a2e; color: #0f0; padding: 40px; }' +
        'h1 { color: #00d4ff; }' +
        '.status { background: #000; padding: 20px; border-radius: 10px; margin-top: 20px; }' +
        'a { color: #00d4ff; }' +
        '</style></head><body>' +
        '<h1>System Status</h1>' +
        '<div class="status">' +
        '<p><strong>Server:</strong> ' + os.hostname() + '</p>' +
        '<p><strong>OS:</strong> ' + os.type() + ' ' + os.release() + '</p>' +
        '<p><strong>Uptime:</strong> ' + Math.floor(os.uptime() / 3600) + ' hours</p>' +
        '<p><strong>Date:</strong> ' + new Date().toISOString() + '</p>' +
        '<p><strong>Node Version:</strong> ' + process.version + '</p>' +
        '<p><strong>Platform:</strong> ' + process.platform + ' ' + process.arch + '</p>' +
        '<p><strong>User:</strong> ' + (process.getuid ? 'uid=' + process.getuid() : 'N/A') + '</p>' +
        '</div>' +
        '<p style="margin-top: 20px;"><a href="/">Back to Home</a></p>' +
        '</body></html>'
    );
});

// Profile endpoint
app.get('/profile', function(req, res) {
    var profileCookie = req.cookies.profile;

    if (profileCookie) {
        // Deserialize the profile cookie
        var decoded = new Buffer(profileCookie, 'base64').toString('ascii');
        console.log('[DESERIALIZE] Received profile cookie: ' + decoded);

        try {
            var profile = serialize.unserialize(decoded);
            console.log('[DESERIALIZE] Deserialized profile: ' + JSON.stringify(profile));

            res.type('text/html').send(
                '<!DOCTYPE html>' +
                '<html><head><title>User Profile</title>' +
                '<style>' +
                'body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 40px; }' +
                'h1 { color: #00d4ff; }' +
                '.profile { background: rgba(0,0,0,0.5); padding: 20px; border-radius: 10px; margin-top: 20px; border: 1px solid #ff6b6b; }' +
                '.field { margin: 10px 0; }' +
                '.label { color: #ff6b6b; font-weight: bold; }' +
                'a { color: #00d4ff; }' +
                '</style></head><body>' +
                '<h1>User Profile</h1>' +
                '<div class="profile">' +
                '<div class="field"><span class="label">Username:</span> ' + (profile.username || 'N/A') + '</div>' +
                '<div class="field"><span class="label">Email:</span> ' + (profile.email || 'N/A') + '</div>' +
                '<div class="field"><span class="label">Role:</span> ' + (profile.role || 'N/A') + '</div>' +
                '</div>' +
                '<p style="margin-top: 20px;"><a href="/">Back to Home</a></p>' +
                '</body></html>'
            );
        } catch (e) {
            console.log('[DESERIALIZE] Error: ' + e.message);
            res.status(500).send('Error deserializing profile: ' + e.message);
        }
    } else {
        // No cookie set - create a default one to demonstrate the flow
        var defaultProfile = {
            username: 'guest',
            email: 'guest@example.com',
            role: 'viewer'
        };
        var serialized = serialize.serialize(defaultProfile);
        var encoded = new Buffer(serialized).toString('base64');

        res.cookie('profile', encoded, { httpOnly: false });
        res.type('text/html').send(
            '<!DOCTYPE html>' +
            '<html><head><title>User Profile</title>' +
            '<style>' +
            'body { font-family: monospace; background: #1a1a2e; color: #eee; padding: 40px; }' +
            'h1 { color: #00d4ff; }' +
            '.info { background: rgba(0,212,255,0.1); border: 1px solid #00d4ff; padding: 20px; border-radius: 10px; margin-top: 20px; }' +
            'code { background: #000; padding: 2px 8px; border-radius: 4px; color: #0f0; }' +
            'a { color: #00d4ff; }' +
            '</style></head><body>' +
            '<h1>Profile Initialized</h1>' +
            '<div class="info">' +
            '<p>A default profile cookie has been set.</p>' +
            '<p style="margin-top: 10px;">Cookie name: <code>profile</code></p>' +
            '<p>Cookie value (Base64): <code>' + encoded + '</code></p>' +
            '<p style="margin-top: 10px;">Decoded: <code>' + serialized + '</code></p>' +
            '<p style="margin-top: 15px;"><a href="/profile">View your profile &rarr;</a></p>' +
            '</div>' +
            '<p style="margin-top: 20px;"><a href="/">Back to Home</a></p>' +
            '</body></html>'
        );
    }
});

/**
 * Login endpoint - sets a serialized profile cookie
 * This makes the cookie flow more realistic
 */
app.post('/login', express.urlencoded({ extended: false }), function(req, res) {
    var username = req.body.username || 'guest';
    var email = req.body.email || 'guest@example.com';

    var profile = {
        username: username,
        email: email,
        role: 'user',
        lastLogin: new Date().toISOString()
    };

    var serialized = serialize.serialize(profile);
    var encoded = new Buffer(serialized).toString('base64');

    res.cookie('profile', encoded, { httpOnly: false });
    res.redirect('/profile');
});

// Start server
app.listen(PORT, '0.0.0.0', function() {
    console.log('===========================================');
    console.log('  Guinea Pig - Node.js Test Server');
    console.log('===========================================');
    console.log('Server listening on port ' + PORT);
    console.log('Running as uid: ' + (process.getuid ? process.getuid() : 'N/A'));
    console.log('');
    console.log('Endpoints:');
    console.log('  GET  /          - Landing page');
    console.log('  GET  /health    - Health check');
    console.log('  GET  /status    - System status');
    console.log('  GET  /profile   - View profile');
    console.log('  POST /login     - Set profile cookie');
});
