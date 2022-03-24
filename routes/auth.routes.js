const {
  StatusCodes,
} = require('http-status-codes');
const router = require("express").Router();
const User = require('../models/User.model')
const bcrypt = require('bcrypt');
const isLoggedOut = require('../middlewear/isLoggedOut');
const isLoggedIn = require('../middlewear/isLoggedIn');
const saltRounds = 10;

const signUpFormData = (req) => {
  return {
    formTitle: 'Signup Form',
    formAction: 'signup',
    routePost: `${req.baseUrl}/signup`
  }
};

const loginFormData = (req) => {
  return {
    formTitle: 'Login Form',
    formAction: 'Login',
    routePost: `${req.baseUrl}/login`
  }
};

function generateFailedSignupForm(req, res, httpStatus, errorMessage) {
  return res
    .status(httpStatus)
    .render('auth/signForm', {
      ...signUpFormData(req),
      error: errorMessage
    });
}

function generateFailedLoginForm(req, res, httpStatus, errorMessage) {
  return res
    .status(httpStatus)
    .render('auth/signForm', {
      ...loginFormData(req),
      error: errorMessage
    });
}

/* GET home page */
router.get("/logout", isLoggedIn, (req, res, next) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        generateFailedLoginForm(req, res, httpStatus.INTERNAL_SERVER_ERROR, "Failed to logout")
      } else {
        res.redirect("/");
      }
    })
  }
});

router.get("/signup", isLoggedOut, (req, res, next) => {
  res.render('auth/signForm', signUpFormData(req));
});

router.post("/signup", isLoggedOut, async (req, res, next) => {
  const { username, password } = req.body;

  if (!username) {
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST,
      'missing username');
  }
  if (!password) {
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST,
      'missing password');
  }
  if (password.length < 8) {
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST,
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
    return generateFailedSignupForm(req, res, StatusCodes.BAD_REQUEST,
      'Could not signup at the moment, please try again.');
  }
});

router.get("/login", isLoggedOut, (req, res, next) => {
  res.render('auth/signForm', loginFormData(req));
});

router.post("/login", isLoggedOut, async (req, res, next) => {
  const { username, password } = req.body;

  if (!username) {
    return generateFailedLoginForm(req, res, StatusCodes.BAD_REQUEST,
      'missing username');
  }
  if (!password) {
    return generateFailedLoginForm(req, res, StatusCodes.BAD_REQUEST,
      'missing password');
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return generateFailedLoginForm(req, res, StatusCodes.BAD_REQUEST,
        'wrong credential');
    }
    const isCorrectPassword = await bcrypt.compare(password, user.password);
    if (isCorrectPassword) {
      req.session.user = user;
      return res.redirect('/');
    } else {
      return generateFailedLoginForm(req, res, StatusCodes.BAD_REQUEST,
        'wrong credential');
    }
  } catch (error) {
    console.log(error);
    return generateFailedLoginForm(req, res, StatusCodes.BAD_REQUEST,
      'Could not login at the moment, please try again.');
  }
});

module.exports = router;
