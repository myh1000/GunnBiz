
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
	birthday: String,
	resetPasswordToken: String,
	resetPasswordExpires: Date,
	parent1email: String,
    parent2email: String,
	DECA_regionalsRoleplay: String,
	DECA_regionalsWritten: String,
	DECA_regionalsTShirt: String,
	DECA_regionalsForms: String,
	DECA_regionalsChecks: String,
	DECA_regionalsRoommate1: String,
	DECA_regionalsRoommate2: String,
	DECA_regionalsRoommate3: String,
	DECA_writtenPartner1: String,
	DECA_writtenPartner2: String,
	DECA_regionalsEventsFinalized: Number,
	DECA_roleplayPartner: String,
	DECA_registrationPayment: String,
	DECA_statesRegistered: Number,
	DECA_statesForms: String,
	DECA_statesChecks: String,
	FBLA_regionalsRoleplay: String,
	FBLA_regionalsWritten: String,
	FBLA_regionalsTShirt: String,
	FBLA_regionalsForms: String,
	FBLA_regionalsChecks: String,
	FBLA_regionalsRoommate1: String,
	FBLA_regionalsRoommate2: String,
	FBLA_regionalsRoommate3: String,
	FBLA_writtenPartner1: String,
	FBLA_writtenPartner2: String,
	FBLA_regionalsEventsFinalized: Number,
	FBLA_roleplayPartner: String,
	FBLA_registrationPayment: String,
	FBLA_statesRegistered: Number,
	FBLA_statesForms: String,
	FBLA_statesChecks: String
});
