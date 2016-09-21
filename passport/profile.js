
var mongoose = require('mongoose');

module.exports = mongoose.model('User',{
	id: String,
	password: String,
	email: String,
	firstName: String,
	lastName: String,
	studentID: Number,
	phoneNumber: Number,
	year: String,
	resetPasswordToken: String,
	resetPasswordExpires: Date
});
