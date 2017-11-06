var express = require('express');
var router = express.Router();

var mysql = require('mysql');

var config = require('../config/config');

var bcrypt = require('bcrypt-nodejs');

var connection = mysql.createConnection(config.db);
connection.connect((error)=> {
	if (error){
		throw error;

	}
});

/* GET home page. */
router.get('/', function(req, res, next) {
	if(req.session.name != undefined){
		console.log(`Welcome, ${req.session.name}`);
	};

  res.render('index', { 
  	name: req.session.name
  });
});

router.get('/register', (req, res, next)=>{
	res.render('register', {});
});

router.post('/registerProcess', (req, res, next)=>{
	// res.json(req.body);
	var name = req.body.name;
	var email = req.body.email;
	var password = req.body.password;
	// make sure email isn't already registered
	const selectQuery = `SELECT * FROM users WHERE email = ?;`;
	connection.query(selectQuery, [email], (error, results)=>{
		// did this return a row? If so, the user already exsists!
		if (results.length != 0) {
			res.redirect('/login?msg=registered');
		} else {
			// this is a new user! insert them!

			// Hash the password first:
			var hash = bcrypt.hashSync(password);

			// var insertQuery = `INSERT INTO users VALUES (DEFAULT,?,?,?);`;
			var insertQuery = `INSERT INTO users (name, email, password) VALUES (?,?,?);`;
			connection.query(insertQuery,[name,email,hash],(error)=>{
				if(error){
					throw error;
				} else {
					res.redirect('/?msg=registered');
				}
			});
		}
	});
});

// somewhere inside the mysql module:
// var connection = {};
// connection.query = function(query, escapedFields, callback) {
// 	does fancy mysql stuff
// 	more fancy stuff
// 	callback(error, results, fields);
// }

router.get('/login', (req, res, next)=>{
	res.render('login', {});
});

router.post('/loginProcess', (req, res, next)=>{
	res.json(req.body);
	var email = req.body.email;
	var password = req.body.password; // English version from user
	// write a query to check if user is in database:
	var selectQuery = `SELECT * FROM users WHERE email = ?;`;

		connection.query(selectQuery, [email],(error,results)=>{
			if(error){
				throw error;
			}else{
				if(results.length == 0){
					// this user isn't in the database. We don't care about their password!
					res.redirect('/login?msg=badUser');
				} else {
					// our select query found something! check the password..
					// call compareSync
					var passwordsMatch = bcrypt.compareSync(password,results[0].password);
					if(passwordsMatch){
						var row = results[0];
						// user in database, password is legit. Log them in.
						req.session.name = results[0].name;
						req.session.id = results[0].id;
						req.session.email = results[0].email;
						res.redirect('/');
					} else {
						// user in db, but password is bad. send them back to login
						res.redirect('/login?msg=badPass');
					}
				}
			}
		});
});




module.exports = router;
