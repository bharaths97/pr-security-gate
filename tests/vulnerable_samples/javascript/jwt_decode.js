const jwt = require("jsonwebtoken");

function inspectToken(token) {
  return jwt.decode(token);
}
