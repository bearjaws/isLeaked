var isLeakedClient = require('../index.js');
var client = new isLeakedClient();
var expect = require('expect.js');
var responses = require('./data/responses.json');
describe('IsLeakedClient', function() {
  describe('isLeaked()', function () {
    it('should return true for a password that has been leaked', function (done) {
      client.isLeakedPassword("asdfgh", function(err, isLeaked) {
          expect(err).to.equal(null)    ;
          expect(isLeaked).to.eql(true);
          done();
      });
    });

    it('should return false for a password that has not been leaked', function (done) {
      client.isLeakedPassword("this password is really unique, maybe", function(err, isLeaked) {
          expect(err).to.equal(null);
          expect(isLeaked).to.eql(false);
          done();
      });
    });
  });

  describe('testPassword()', function () {
      it('should pass owasp validation for a secure passphrase', function (done) {
        client.testPassword("A day may come when the courage of men fails", function(err, body) {
            expect(body).to.eql(responses['A day may come']);
            expect(err).to.be.equal(null);
            done();
        });
      });

    it('should fail owasp validation for a poor password', function (done) {
      client.testPassword("asdfgh", function(err, body) {
          expect(body).to.eql(responses['should return owasp validation']);
          expect(err).to.be.equal(null);
          done();
      });
    });
  });
});
