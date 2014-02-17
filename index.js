'use strict';
var internals = {
  defaults: {},
  verify: null
};

exports.register = function (plugin, options, next) {
  internals.error = plugin.hapi.error;
  internals.verify = options.verify;

  plugin.auth.scheme('bearer', internals.scheme);

  next();
};

internals.scheme = function (server, options) {
  return {
    authenticate: internals.authenticate
  };
};

internals.authenticate = function (request, reply) {
  var token;

  token = request.headers.authorization;
  if (token) {
    token = token.split(' ')[1];
  } else {
    if (request.payload && request.payload.access_toke) {
      token = request.payload.access_token;
    } else if (request.query && request.query.access_token) {
      token = request.query.access_token;
    } else {
      token = null;
    }
  }

  if (!token) {
    return reply(internals.error.unauthorized('No bearer token found', 'bearer'));
  }

  if (!internals.verify) {
    return reply(internals.error.internal('Bearer Authentication requires a verify callback'));
  }

  internals.verify(token, function (err, user, info) {
    info = info || {};

    if (err) {
      return reply(internals.error.unauthorized(err));
    }

    if (!user) {
      return reply(info.message || 'Unable to verify bearer token');
    }

    reply(null, {credentials: user, artifacts: info});
  });
};
