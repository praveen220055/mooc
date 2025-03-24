// authMiddleware.js


const jwt = require('jsonwebtoken');

function verifyToken(req, res, next) {
  // Token should be sent in the header as "Bearer <token>"
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).json({ success: false, message: 'No token provided.' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ success: false, message: 'Failed to authenticate token.' });
    }
    req.user = decoded;
    next();
  });
}

function ensureRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ success: false, message: 'Access denied.' });
    }
    next();
  };
}

module.exports = { verifyToken, ensureRole };
