const jwt = require("jsonwebtoken");

const config = process.env;

const verifyAdminToken = (req, res, next) => {
  const token =
    req.body.token || req.query.token || req.headers["x-access-token"];

  if (!token) {
    return res.status(401).send("Please provide a token for authentication.");
  }
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    req.user = decoded;
    console.log(req.user);
    if (req.user.role == "User") {
      return res
        .status(403)
        .send("This is a User token, no authorized for Admin privileges");
    }

    if (req.user.role != "Admin") {
      return res
        .status(403)
        .send("Token is neither User or Admin role, please recheck your token");
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

module.exports = verifyAdminToken;
