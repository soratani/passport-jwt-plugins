import passport from "passport-strategy";
import util from "util";
import assign from "./helpers/assign";

function JwtStrategy(options, verify) {
  passport.Strategy.call(this);
  this.name = "jwt";

  this._secretOrKeyProvider = options.secretOrKeyProvider;

  if (options.secretOrKey) {
    if (this._secretOrKeyProvider) {
      throw new TypeError(
        "JwtStrategy has been given both a secretOrKey and a secretOrKeyProvider"
      );
    }
    this._secretOrKeyProvider = function (request, rawJwtToken, done) {
      done(null, options.secretOrKey);
    };
  }

  if (!this._secretOrKeyProvider) {
    throw new TypeError("JwtStrategy requires a secret or key");
  }

  this._verify = verify;
  if (!this._verify) {
    throw new TypeError("JwtStrategy requires a verify callback");
  }

  this._jwtFromRequest = options.jwtFromRequest;
  if (!this._jwtFromRequest) {
    throw new TypeError(
      "JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)"
    );
  }

  this._passReqToCallback = options.passReqToCallback;
  var jsonWebTokenOptions = options.jsonWebTokenOptions || {};
  this._verifOpts = assign({}, jsonWebTokenOptions, {
    audience: options.audience,
    issuer: options.issuer,
    algorithms: options.algorithms,
    ignoreExpiration: !!options.ignoreExpiration,
  });
}
util.inherits(JwtStrategy, passport.Strategy);

JwtStrategy.JwtVerifier = require("./verify_jwt");

JwtStrategy.prototype.authenticate = function (req, options) {
  var self = this;

  var token = self._jwtFromRequest(req);

  if (!token) {
    var verified = function (err, user, info) {
      if (err) {
        return self.error(err);
      } else if (!user) {
        return self.fail(info);
      } else {
        return self.success(user, info);
      }
    };
    try {
      if (self._passReqToCallback) {
        self._verify(req, null, verified);
      } else {
        self._verify(null, verified);
      }
    } catch (ex) {
      self.error(ex);
    }
    return;
  }

  this._secretOrKeyProvider(
    req,
    token,
    function (secretOrKeyError, secretOrKey) {
      if (secretOrKeyError) {
        self.fail(secretOrKeyError);
      } else {
        // Verify the JWT
        JwtStrategy.JwtVerifier(
          token,
          secretOrKey,
          self._verifOpts,
          function (jwt_err, payload) {
            if (jwt_err) {
              return self.fail(jwt_err);
            } else {
              // Pass the parsed token to the user
              var verified = function (err, user, info) {
                if (err) {
                  return self.error(err);
                } else if (!user) {
                  return self.fail(info);
                } else {
                  return self.success(user, info);
                }
              };

              try {
                if (self._passReqToCallback) {
                  self._verify(req, payload, verified);
                } else {
                  self._verify(payload, verified);
                }
              } catch (ex) {
                self.error(ex);
              }
            }
          }
        );
      }
    }
  );
};

export default JwtStrategy;
