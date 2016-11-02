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
      res.render('home', { title: 'Gunn Business - Home' });
    });
	app.get('/news', function(req, res, next) {
      res.render('news', { title: 'Gunn Business - News' });
    });
	app.get('/projects', function(req, res, next) {
      res.render('projects', { title: 'Gunn Business - Projects' });
    });
	app.get('/ae', function(req, res, next) {
      res.render('ae', { title: 'Gunn Business - American Enterprise' });
    });
	app.get('/pb', function(req, res, next) {
      res.render('pb', { title: 'Gunn Business - Partnership with Business' });
    });
	app.get('/cs', function(req, res, next) {
      res.render('cs', { title: 'Gunn Business - Community Service' });
    });
    /* GET About page. */
    app.get('/about', function(req, res, next) {
      res.render('about', { title: 'Gunn Business - About' });
    });
    /* GET index page. */
    app.get('/index', function(req, res, next) {
      res.render('home', { title: 'Gunn Business - Home' });
    });
    /* GET events page. */
    app.get('/events', function(req, res, next) {
      res.render('events', { title: 'Gunn Business - Events' });
    });
	/* GET New User page. */
	app.get('/login', function(req, res) {
		if(req.isAuthenticated(req, res)) {
            res.redirect('/profile');
        } else {
			res.render('login', { title: 'Gunn Business - Login', message: req.flash('message')});
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
			res.render('registration', { title: 'Gunn Business - User Registration', message: req.flash('message')});
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
	// app.get('/forgot', function(req, res) {
	// 	if(req.isAuthenticated(req, res)) {
    //         res.redirect('/profile');
    //     } else {
	// 		res.render('forgot', {
	// 			user: req.user,
	// 			title: 'Gunn Business - Forgot Password',
	// 			message: req.flash('message')
	// 		});
	// 	}
	// });
	// app.post('/forgot', function(req, res, next) {
	// 	async.waterfall([
	// 	    function(done) {
	// 	      crypto.randomBytes(20, function(err, buf) {
	// 	        var token = buf.toString('hex');
	// 	        done(err, token);
	// 	      });
	// 	    },
	// 	    function(token, done) {
	// 	      User.findOne({ email: req.body.email }, function(err, user) {
	// 	        if (!user) {
	// 	          req.flash('error', 'No account with that email address exists.');
	// 	          return res.redirect('/forgot');
	// 	        }
	//
	// 	        user.resetPasswordToken = token;
	// 	        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
	// 			console.log(token);
	// 	        user.save(function(err) {
	// 	          done(err, token, user);
	// 	        });
	// 	      });
	// 	    }
	// 	    // function(token, user, done) {
	// 		// 	var smtpTransport = nodemailer.createTransport('SMTP', {
	// 		// 			service: 'SendGrid',
	// 		// 			auth: {
	// 		// 			user: '',
	// 		// 			pass: ''
	// 		// 		}
	// 		// 	});
	// 		// 	var mailOptions = {
	// 		// 		to: user.email,
	// 		// 		from: 'passwordreset@demo.com',
	// 		// 		subject: 'Node.js Password Reset',
	// 		// 		text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
	// 		// 		'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
	// 		// 		'http://' + req.headers.host + '/reset/' + token + '\n\n' +
	// 		// 		'If you did not request this, please ignore this email and your password will remain unchanged.\n'
	// 		// 	};
	// 		// 	smtpTransport.sendMail(mailOptions, function(err) {
	// 		// 		req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
	// 		// 		done(err, 'done');
	// 		// 	});
	// 		// }
	// 	], function(err) {
	// 		if (err) return next(err);
	// 		res.redirect('/forgot');
	// 	});
	// });
	// app.get('/reset/:token', function(req, res) {
	// 	User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
	// 		if (!user) {
	// 			req.flash('error', 'Password reset token is invalid or has expired.');
	// 			return res.redirect('/forgot');
	// 		}
	// 		res.render('reset', {
	// 			user: req.user,
	// 			title: 'Gunn Business - Reset Password'
	// 		});
	// 	});
	// });
	// app.post('/reset/:token', function(req, res) {
	// 	async.waterfall([
	// 		function(done) {
	// 			User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
	// 			if (!user) {
	// 			  req.flash('error', 'Password reset token is invalid or has expired.');
	// 			  return res.redirect('back');
	// 			}
	//
	// 			user.password = bCrypt.hashSync(req.body.password, bCrypt.genSaltSync(10), null);
	// 			user.resetPasswordToken = undefined;
	// 			user.resetPasswordExpires = undefined;
	//
	// 			user.save(function(err) {
	// 				req.logIn(user, function(err) {
	// 				done(err, user);
	// 				});
	// 			});
	// 		});
	// 	}
	// 	], function(err) {
	// 	res.redirect('/');
	// 	});
	// });
	/* GET Profile Page */
	app.get('/profile', isAuthenticated, function(req, res){
		res.render('profile', { title: 'Gunn Business - Profile', user: req.user, message: req.flash('message')});
	});
	app.post('/setinfo', function(req, res) {
		req.user.firstName = req.body.firstName;
		req.user.lastName = req.body.lastName;
		req.user.phoneNumber = req.body.phoneNumber;
		req.user.grade = req.body.grade;
		req.user.birthday = req.body.birthday;
		req.user.studentID = req.body.studentID;
		req.user.parent1email = req.body.parent1email;
		req.user.parent2email = req.body.parent2email;
		req.user.save(function (err, member) {
			if (err) return console.error(err);
		});
		res.redirect('/profile');
	});
	app.post('/setDECARegionals', function(req, res)
	{
		if (req.body.submitbutton == 'cancel'){
			req.user.DECA_regionalsWritten = null;
			req.user.DECA_writtenPartner1 = null;
			req.user.DECA_writtenPartner2 = null;
			req.user.DECA_regionalsRoleplay = null;
			req.user.DECA_roleplayPartner = null;
			// req.user.DECA_regionalsTShirt = req.body.DECA_regionalsTShirt;
			req.user.DECA_regionalsRegistered = null;
			req.user.save(function (err, member){
				if (err) return console.error(err);
				console.log("saved");
			});
			res.redirect('/profile');
		}
		else {
			req.user.DECA_regionalsWritten = req.body.DECA_regionalsWritten;
			req.user.DECA_writtenPartner1 = req.body.DECA_writtenPartner1;
			req.user.DECA_writtenPartner2 = req.body.DECA_writtenPartner2;
			req.user.DECA_regionalsRoleplay = req.body.DECA_regionalsRoleplay;
			req.user.DECA_roleplayPartner = req.body.DECA_roleplayPartner;
			// req.user.DECA_regionalsTShirt = req.body.DECA_regionalsTShirt;
			req.user.DECA_regionalsRegistered = 1;
			req.user.save(function (err, member) {
				if (err) return console.error(err);
				console.log("saved");
			});
			res.redirect('/profile');
		}
	});
	app.post('/setFBLARegionals', function(req, res)
	{
		if (req.body.submitbutton == 'cancel'){
			req.user.FBLA_regionalsEvent = null;
			req.user.FBLA_eventPartner1 = null;
			req.user.FBLA_eventPartner2 = null;
			req.user.FBLA_eventPartner3 = null;
			req.user.FBLA_eventPartner4 = null;
			// req.user.FBLA_regionalsTShirt = req.body.FBLA_regionalsTShirt;
			req.user.FBLA_regionalsRegistered = null;
			req.user.save(function (err, member){
				if (err) return console.error(err);
				console.log("saved");
			});
			res.redirect('/profile');
		}
		else {
			req.user.FBLA_regionalsEvent = req.body.FBLA_regionalsEvent;
			req.user.FBLA_eventPartner1 = req.body.FBLA_eventPartner1;
			req.user.FBLA_eventPartner2 = req.body.FBLA_eventPartner2;
			req.user.FBLA_eventPartner3 = req.body.FBLA_eventPartner3;
			req.user.FBLA_eventPartner4 = req.body.FBLA_eventPartner4;
			// req.user.FBLA_regionalsTShirt = req.body.FBLA_regionalsTShirt;
			req.user.FBLA_regionalsRegistered = 1;
			req.user.save(function (err, member) {
				if (err) return console.error(err);
				console.log("saved");
			});
			res.redirect('/profile');
		}
	});
	app.get('/admin', isAuthenticated, function(req, res){
		if (req.user && req.user.isAdmin === true) {
			var userMap = {};
			mongoose.model("User").find({}, function(err, users)
			{
			    users.forEach(function(user) {
					userMap[user._id] = user;
				});
				console.log(userMap);
				res.render('admin', { title: 'Gunn Business - Admin Panel', user: req.user, members: userMap, message: req.flash('message')});
			});
        } else {
			res.redirect('/profile');
		}
	});
	app.post('/admin', isAuthenticated, function(req, res){
		if (req.user && req.user.isAdmin === true) {
			var userMap = {};
			req.body.email.forEach(function(email, index) {
				mongoose.model("User").findOne({ 'email': req.body.email[index]}, function(err, user) {
					if (err){
						console.log(err)
					}
					console.log(email)
					if (! user) {
						res.json('nope');
						console.log('nope');
					}
					else {
						console.log(req.body["DECA_registrationPayment" + index],"same");
						user.DECA_registrationPayment = req.body["DECA_registrationPayment" + index];
						user.DECA_regionalsChecks = req.body["DECA_regionalsChecks" + index];
						user.DECA_regionalsForms = req.body["DECA_regionalsForms" + index];
						user.FBLA_registrationPayment = req.body["FBLA_registrationPayment" + index];
						user.FBLA_regionalsChecks = req.body["FBLA_regionalsChecks" + index];
						user.FBLA_regionalsForms = req.body["FBLA_regionalsForms" + index];
						user.save(function (err) {
							if (err) return console.error(err);
						});
					}
				})
			});
		res.redirect('admin');
        } else {
			res.redirect('/profile');
		}
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
