const passport = require('passport-strategy');
const util = require('util');
const OAuth2 = require('oauth').OAuth2;
const InternalOAuthError = require("passport-oauth2").InternalOAuthError;

function FacebookStrategy(options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }
  if (!verify) {
    throw new TypeError('FacebookStrategy requires a verify callback');
  }

  passport.Strategy.call(this);
  this.name = 'meta-facebook';
  this._verify = verify;

  // Gunakan URL dari opsi atau gunakan URL default
  const oauthURL = options.oauthURL || 'https://www.facebook.com/v14.0/dialog/oauth';
  const tokenURL = options.tokenURL || 'https://graph.facebook.com/v14.0/oauth/access_token';
  this._accountsURL = options.accountsURL || 'https://graph.facebook.com/v14.0/me';
  this._pagesURL = options.pagesURL || 'https://graph.facebook.com/v14.0/me/accounts?fields=id,name,picture';

  this._oauth2 = new OAuth2(
    options.clientID,
    options.clientSecret,
    '',
    oauthURL,
    tokenURL
  );
}

util.inherits(FacebookStrategy, passport.Strategy);

FacebookStrategy.prototype.authenticate = function (req, options) {
  if (!req.query.code) {
    const authURL = this._oauth2.getAuthorizeUrl({
      redirect_uri: options.callbackURL,
      scope: options.scope,
      response_type: 'code'
    });
    this.redirect(authURL);
  } else {
    const code = req.query.code;
    this._oauth2.getOAuthAccessToken(
      code,
      {
        grant_type: 'authorization_code',
        redirect_uri: options.callbackURL
      },
      (err, accessToken, refreshToken, params) => {
        if (err) {
          return this.error(err);
        }
        this.userProfile(accessToken, (err, profile) => {
          if (err) {
            return this.error(err);
          }
          this._verify(accessToken, refreshToken, profile, (err, user, info) => {
            if (err) {
              return this.error(err);
            }
            if (!user) {
              return this.fail(info);
            }
            this.success(user, info);
          });
        });
      }
    );
  }
};

FacebookStrategy.prototype.userProfile = function (accessToken, done) {
  const self = this;
  
  function getFacebookAccounts(callback) {
    self._oauth2.get(self._accountsURL, accessToken, function (err, body, res) {
      if (err) {
        return callback(new InternalOAuthError("Failed to fetch user accounts", err));
      }
      try {
        const json = JSON.parse(body);
        callback(null, json);
      } catch (e) {
        callback(e);
      }
    });
  }

  function getFacebookPages(callback) {
    self._oauth2.get(self._pagesURL, accessToken, function (err, body, res) {
      if (err) {
        return callback(new InternalOAuthError("Failed to fetch additional pages accounts", err));
      }
      try {
        const json = JSON.parse(body);
        if (json.data.length > 0 && json.data !== null) {
          const pictures = json.data.map((page) => page.picture.data.url);
          json.data.forEach((page) => delete page.picture);
          delete json.paging;
          json.pictures = pictures;
        }
        callback(null, json);
      } catch (e) {
        callback(e);
      }
    });
  }

  getFacebookAccounts(function (err, accountsData) {
    if (err) {
      return done(err);
    }
    getFacebookPages(function (err, additionalData) {
      if (err) {
        return done(err);
      }
      try {
        const dataFacebook = {
          provider: "facebook",
          accounts: accountsData,
          pages: additionalData
        };
        done(null, dataFacebook);
      } catch (e) {
        done(e);
      }
    });
  });
};

module.exports = FacebookStrategy;
