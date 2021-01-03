const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');

const User = require('../models/User');

router.get('/login', (req, res) => res.render('Login'));

router.get('/register', (req, res) => res.render('Register'));

router.post('/register', (req, res) => {
	const { name, email, password, password2 } = req.body;
	let errors = [];
	
	if(!name || !email || !password || !password2) {
		errors.push({ msg: 'Please fill all the fields' });
	}
	
	if(password !== password2) {
		errors.push({ msg: 'Password fields do not match' });
	}
	
	if(password.length < 6) {
		errors.push({ msg: 'Password length must be 6 characters or more' });
	}
	
	if(errors.length > 0) {
		res.render('register', {
			errors,
			name,
			email,
			password,
			password2
		});
	} else {
		//validation passed
		User.findOne({ email: email }).then(user => {
			//console.log(user);
			if(user) {
				//user already exists
				errors.push({ msg: 'User emaill already registered' });
				res.render('register', {
					errors,
					name,
					email,
					password,
					password2
				});
			} else {
				const newUser = new User({
					name,
					email,
					password
				});
				
				bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err, hash) => {
					if(err) throw err;
					newUser.password = hash;
					newUser.save().then(user => {
						req.flash('success_msg', 'You are now registered');
						res.redirect('/users/login');
					}).catch(err => console.log(err));
				}))
			}
		});
	}
});

router.post('/login', (req, res, next) => {
	passport.authenticate('local', {
		successRedirect: '/dashboard',
		failureRedirect: '/users/login',
		failureFlash: true
	})(req, res, next);
});

router.get('/logout', (req, res) => {
	req.logout();
	req.flash('success_msg', 'You have logged out of MemeVerse');
	res.redirect('/users/login');
});

module.exports = router;