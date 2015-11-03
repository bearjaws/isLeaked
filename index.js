var bluebird = require('bluebird');
var request = require('request');

/**
 * Called when a server is no longer available, sets active to false,
 * then after a delay of 30 seconds reactivates it.
 * @param {string} host    The host to inactivate.
 * @param {object[]} servers The servers configuration array.
 */
function setInactiveAndReset(host, servers) {
    servers.forEach(function(server) {
        if (server.host === host) {
            server.active = false;
            setTimeout(function() {
                server.active = true;
            }, 30000);
        }
    });
}

function IsLeaked(servers, owaspConfig) {
    //@TODO add joi validation of these objects
    if (typeof servers === 'object' && servers !== null) {
        this.servers = servers;
    } else {
        this.servers = require('./servers.json');
    }

    if (typeof owaspConfig === 'object' && owaspConfig !== null) {
        this.owaspConfig = owaspConfig;
    } else {
        this.owaspConfig = null;
    }
    // Standard network connection errors
    this.errors = [
        'ECONNREFUSED',
        'ETIMEDOUT',
        'ECONNRESET'
    ];
}

/**
 * Returns a servers ip address to be used when performing API requests
 * @return {String} - The IP address in string form
 */
IsLeaked.prototype.getWeightedServer = function() {
    var len = this.servers.length;
    var check = Math.random();
    for(var i = 0; i < len; i++) {
        var server = this.servers[i];
        if (server.active === true && server.weight >= check) {
            return server.host;
        }
    }
    // Remove weight check to prevent race condition for weight only existing on offline servers
    for(var i = 0; i < len; i++) {
        var server = this.servers[i];
        if (server.active === true) {
            return server.host;
        }
    }

    throw new Error("No servers are available to proccess your request.");
}

/**
 * Checks for the existence of a password in a know password list.
 * @param  {string}   password The password to verify against isLeaked
 * @param  {Function} cb       Ca;; back function(err, result)
 */
IsLeaked.prototype.isLeakedPassword = function(password, cb) {
    var self = this;
    var host = self.getWeightedServer();
    return new bluebird(function(resolve, reject) {
        return request({
            url: host + "/password/isLeaked",
            method: "POST",
            json: true,
            body: { password: password }
        }, function(err, res, body) {
            if (err && self.errors.indexOf(err.code) !== -1) {
                setInactiveAndReset(host, self.servers);
                return self.isLeakedPassword(password, cb);
            }

            if (res.statusCode !== 200) {
                reject(body);
            }
            resolve(body.isLeaked === true);
        });
    }).asCallback(cb);
}

/**
 * Tests the password against OWASP and isLeaked, allowing you to consolidate your password verification
 * You can check if a password is `safe` by reading the `strong` property from the response.
 * @param  {string}   password The password to verify against isLeaked
 * @param  {[object]}   owaspConfig OWASP config as defined at https://www.npmjs.com/package/owasp-password-strength-test
 * @param  {Function} cb   callback function (err, body), where body is the type returned at
 *                                https://www.npmjs.com/package/owasp-password-strength-test
 */
IsLeaked.prototype.testPassword = function(password, cb) {
    var self = this;
    var host = self.getWeightedServer();
    var body = {
        password: password
    }

    if(this.owaspConfig !== null) {
        body.config = this.owaspConfig;
    }

    return new bluebird(function(resolve, reject) {
        return request({
            url: host + "/password/test",
            method: "POST",
            json: true,
            body: body
        }, function(err, res, body) {
            if (err && self.errors.indexOf(err.code) !== -1) {
                setInactiveAndReset(host, self.servers);
                return self.testPassword(password, cb);
            }

            if (res.statusCode !== 200) {
                reject(body);
            }
            resolve(body);
        });
    }).asCallback(cb);
}

module.exports = IsLeaked;
