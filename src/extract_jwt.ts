import url from "url";
import { parseAuthHeader } from "./auth_header";

var AUTH_HEADER = "authorization",
  LEGACY_AUTH_SCHEME = "JWT",
  BEARER_AUTH_SCHEME = "bearer";

var extractors: Record<any, any> = {};

extractors.fromHeader = function (header_name) {
  return function (request) {
    var token = null;
    if (request.headers[header_name]) {
      token = request.headers[header_name];
    }
    return token;
  };
};

extractors.fromBodyField = function (field_name) {
  return function (request) {
    var token = null;
    if (
      request.body &&
      Object.prototype.hasOwnProperty.call(request.body, field_name)
    ) {
      token = request.body[field_name];
    }
    return token;
  };
};

extractors.fromUrlQueryParameter = function (param_name) {
  return function (request) {
    var token = null,
      parsed_url = url.parse(request.url, true);
    if (
      parsed_url.query &&
      Object.prototype.hasOwnProperty.call(parsed_url.query, param_name)
    ) {
      token = parsed_url.query[param_name];
    }
    return token;
  };
};

extractors.fromAuthHeaderWithScheme = function (auth_scheme) {
  var auth_scheme_lower = auth_scheme.toLowerCase();
  return function (request) {
    var token = null;
    if (request.headers[AUTH_HEADER]) {
      var auth_params = parseAuthHeader(request.headers[AUTH_HEADER]);
      if (
        auth_params &&
        auth_scheme_lower === auth_params.scheme.toLowerCase()
      ) {
        token = auth_params.value;
      }
    }
    return token;
  };
};

extractors.fromAuthHeaderAsBearerToken = function () {
  return extractors.fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
};

extractors.fromExtractors = function (extractors) {
  if (!Array.isArray(extractors)) {
    throw new TypeError("extractors.fromExtractors expects an array");
  }

  return function (request) {
    var token = null;
    var index = 0;
    while (!token && index < extractors.length) {
      token = extractors[index].call(this, request);
      index++;
    }
    return token;
  };
};

extractors.versionOneCompatibility = function (options) {
  var authScheme = options.authScheme || LEGACY_AUTH_SCHEME,
    bodyField = options.tokenBodyField || "auth_token",
    queryParam = options.tokenQueryParameterName || "auth_token";

  return function (request) {
    var authHeaderExtractor = extractors.fromAuthHeaderWithScheme(authScheme);
    var token = authHeaderExtractor(request);

    if (!token) {
      var bodyExtractor = extractors.fromBodyField(bodyField);
      token = bodyExtractor(request);
    }

    if (!token) {
      var queryExtractor = extractors.fromUrlQueryParameter(queryParam);
      token = queryExtractor(request);
    }

    return token;
  };
};

export default extractors;
