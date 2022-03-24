
const isLoggedOut = (req, res, next) => {
  if (req.session.user) {
    return res.redirect('/main');
  }
  next();
};

module.exports = isLoggedOut;
