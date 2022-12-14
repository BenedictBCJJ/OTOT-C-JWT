const jwt = require("jsonwebtoken");

const config = process.env;

const verifyToken = (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers["x-access-token"];

  if (!token) {
    return res.status(401).send("Please provide a token for authentication.");
  }
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
    // console.log(req.user);
    if (req.user.role == "Guest") {
      return res
        .status(403)
        .send(
          "This token is a Guest Token. This page is for Users and Admins only"
        );
    }

    if (req.user.role != "User" && req.user.role != "Admin") {
      return res
        .status(403)
        .send("This token has an invalid role and has no authorization.");
    }
  } catch (err) {
    return res
      .status(401)
      .send(
        "Token could not be decoded, cannot be authenticated as member of this platform."
      );
  }
  return next();
};

module.exports = verifyToken;
