var isLeakedClient = require('../index.js');
var fs = require('fs');
var client = new isLeakedClient();
var expect = require('expect.js');
var responses = require('./data/responses.json');
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
describe('IsLeakedClient', function() {
    describe('isLeaked()', function () {
        it('should return true for a password that has been leaked', function (done) {
            client.isLeakedPassword("asdfgh", function(err, isLeaked) {
                expect(err).to.equal(null)    ;
                expect(isLeaked).to.eql(true);
                done();
            });
        });

        it('should be able to call isLeaked() as a promise.', function (done) {
            return client.isLeakedPassword("asdfgh").then(function(isLeaked) {
                expect(isLeaked).to.eql(true);
                done();
            }).catch(function(err) {
                done(err);
            });;
        });

        it('should return false for a password that has not been leaked', function (done) {
            client.isLeakedPassword("this password is really unique, maybe", function(err, isLeaked) {
                expect(err).to.equal(null);
                expect(isLeaked).to.eql(false);
                done();
            });
        });

        it('should automatically switch to different server if conn fails', function (done) {
            var servers = [{
                    "host": "http://localhost:1133",
                    "weight": 1,
                    "active": true
            }, {
                    "host": "https://localhost:9455",
                    "weight": 1,
                    "active": true
            }];

            var client = new isLeakedClient(servers);

            client.isLeakedPassword("this password is special", function(err, isLeaked) {
                expect(err).to.equal(null);
                expect(isLeaked).to.eql(false);
                done();
            });
        });
    });

    describe('owaspCheckPassword()', function () {
        it('should pass owasp validation for a secure passphrase', function (done) {
            client.owaspCheckPassword("A day may come when the courage of men fails", function(err, body) {
                expect(body).to.eql(responses['A day may come']);
                expect(err).to.be.equal(null);
                done();
            });
        });

        it('should be able to call testPassword() using promises', function (done) {
            return client.owaspCheckPassword("Promis3s please.").then(function(body) {
                expect(body).to.eql(responses['promises please']);
                done();
            }).catch(function(err) {
                done(err);
            });
        });

        it('should fail owasp validation for a poor password', function (done) {
            client.owaspCheckPassword("asdfgh", function(err, body) {
                expect(body).to.eql(responses['should return owasp validation']);
                expect(err).to.be.equal(null);
                done();
            });
        });
    });
});
