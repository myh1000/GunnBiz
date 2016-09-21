var User = require('../passport/profile');
var async = require('async');
var crypto = require('crypto');
var bCrypt = require('bcrypt-nodejs');

module.exports = function(app, passport){

	var mongoose = require('mongoose')
	app.use(function (req, res, next) {
		res.locals.login = req.isAuthenticated();
		next();
	});

    /* GET home page. */
    app.get('/', function(req, res, next) {
      res.render('home', { title: 'Gunn FBLA - Home' });
    });
	app.get('/news', function(req, res, next) {
      res.render('news', { title: 'Gunn FBLA - News' });
    });
	app.get('/projects', function(req, res, next) {
      res.render('projects', { title: 'Gunn FBLA - Projects' });
    });
	app.get('/ae', function(req, res, next) {
      res.render('ae', { title: 'Gunn FBLA - American Enterprise' });
    });
	app.get('/pb', function(req, res, next) {
      res.render('pb', { title: 'Gunn FBLA - Partnership with Business' });
    });
	app.get('/cs', function(req, res, next) {
      res.render('cs', { title: 'Gunn FBLA - Community Service' });
    });
    /* GET About page. */
    app.get('/about', function(req, res, next) {
      res.render('about', { title: 'Gunn FBLA - About' });
    });
    /* GET index page. */
    app.get('/index', function(req, res, next) {
      res.render('home', { title: 'Gunn FBLA - Home' });
    });
    /* GET events page. */
    app.get('/events', function(req, res, next) {
      res.render('events', { title: 'Gunn FBLA - Events' });
    });
	/* GET New User page. */
	app.get('/login', function(req, res) {
		if(req.isAuthenticated(req, res)) {
            res.redirect('/profile');
        } else {
			res.render('login', { title: 'Gunn FBLA - Login', message: req.flash('message')});
		}
	});
	app.post('/login', passport.authenticate('login', {
		successRedirect: '/profile',
		failureRedirect: '/login',
		failureFlash : true
	}));
	/* GET New User page. */
	app.get('/registration', function(req, res) {
		if(req.isAuthenticated(req, res)) {
            res.redirect('/profile');
        } else {
			res.render('registration', { title: 'Gunn FBLA - User Registration', message: req.flash('message')});
		}
	});
    /* Handle Registration POST */
    app.post('/registration', passport.authenticate('signup', {
		successRedirect: '/profile',
		failureRedirect: '/registration',
		failureFlash : true
	}));
	app.get('/logout', function(req, res){
		req.logout();
		res.redirect('/');
	});
	app.get('/forgot', function(req, res) {
		if(req.isAuthenticated(req, res)) {
            res.redirect('/profile');
        } else {
			res.render('forgot', {
				user: req.user,
				title: 'Gunn FBLA - Forgot Password',
				message: req.flash('message')
			});
		}
	});
	app.post('/forgot', function(req, res, next) {
		async.waterfall([
		    function(done) {
		      crypto.randomBytes(20, function(err, buf) {
		        var token = buf.toString('hex');
		        done(err, token);
		      });
		    },
		    function(token, done) {
		      User.findOne({ email: req.body.email }, function(err, user) {
		        if (!user) {
		          req.flash('error', 'No account with that email address exists.');
		          return res.redirect('/forgot');
		        }

		        user.resetPasswordToken = token;
		        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
				console.log(token);
		        user.save(function(err) {
		          done(err, token, user);
		        });
		      });
		    }
		    // function(token, user, done) {
			// 	var smtpTransport = nodemailer.createTransport('SMTP', {
			// 			service: 'SendGrid',
			// 			auth: {
			// 			user: 'myh1000',
			// 			pass: 'J23eeeJLS'
			// 		}
			// 	});
			// 	var mailOptions = {
			// 		to: user.email,
			// 		from: 'passwordreset@demo.com',
			// 		subject: 'Node.js Password Reset',
			// 		text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
			// 		'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
			// 		'http://' + req.headers.host + '/reset/' + token + '\n\n' +
			// 		'If you did not request this, please ignore this email and your password will remain unchanged.\n'
			// 	};
			// 	smtpTransport.sendMail(mailOptions, function(err) {
			// 		req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
			// 		done(err, 'done');
			// 	});
			// }
		], function(err) {
			if (err) return next(err);
			res.redirect('/forgot');
		});
	});
	app.get('/reset/:token', function(req, res) {
		User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
			if (!user) {
				req.flash('error', 'Password reset token is invalid or has expired.');
				return res.redirect('/forgot');
			}
			res.render('reset', {
				user: req.user,
				title: 'Gunn FBLA - Reset Password'
			});
		});
	});
	app.post('/reset/:token', function(req, res) {
		async.waterfall([
			function(done) {
				User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
				if (!user) {
				  req.flash('error', 'Password reset token is invalid or has expired.');
				  return res.redirect('back');
				}

				user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null);
				user.resetPasswordToken = undefined;
				user.resetPasswordExpires = undefined;

				user.save(function(err) {
					req.logIn(user, function(err) {
					done(err, user);
					});
				});
			});
		}
		], function(err) {
		res.redirect('/');
		});
	});
	/* GET Home Page */
	app.get('/profile', isAuthenticated, function(req, res){
		res.render('profile', { title: 'Gunn FBLA - Profile', user: req.user });
	});

    // return app;
}

var isAuthenticated = function (req, res, next) {
	// if user is authenticated in the session, call the next() to call the next request handler
	// Passport adds this method to request object. A middleware is allowed to add properties to
	// request and response objects
	if (req.isAuthenticated())
		return next();
	// if the user is not authenticated then redirect him to the login page
	res.redirect('/');
}
