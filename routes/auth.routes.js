const {
  StatusCodes,
} = require('http-status-codes');
const router = require("express").Router();
const User = require('../models/User.model')
const bcrypt = require('bcrypt')
const saltRounds = 10;

const signUpFormData = (req) => {
  return {
    formTitle: 'Signup Form',
    formAction: 'signup',
    routePost: `${req.baseUrl}/signup`
  }
};

function generateFailedSignupForm(req, res, httpStatus, errorStatus, errorMessage) {
  return res
    .status(httpStatus)
    .render('auth/signForm', {
      ...signUpFormData(req),
      error: {
        status: errorStatus,
        message: errorMessage
      }
    });
}

/* GET home page */
router.get("/signup", (req, res, next) => {
  res.render('auth/signForm', signUpFormData(req));
});

router.post("/signup", async (req, res, next) => {
  const { username, password } = req.body;

  if (!username) {
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST, 'USERNAME',
      'missing username');
  }
  if (!password) {
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST, 'PASSWORD',
    'missing password');
  }
  if (password.length < 8) {
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST, 'PASSWORD',
    'weak password...');
  }

  try {
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = await User.create({
      username,
      password: hashedPassword
    });
    req.session.user = user;
    res.redirect('/');
  } catch (error) {
    console.log(error);
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST, 'ERROR',
    'Could not signup at the moment, please try again.');
  }
});

module.exports = router;
