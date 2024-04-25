import jwt from "jsonwebtoken";

export default function (token, secretOrKey, options, callback) {
  return jwt.verify(token, secretOrKey, options, callback);
}
