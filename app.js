//Verifies the stateless tokenId received from OpenAM
//Simon Moffatt 2 June 2015
//Based on https://github.com/auth0/node-jsonwebtoken

// Import libs
var jwt = require('jsonwebtoken'); // 3rd party JWT verification library
var http = require('http'); // To make http req to OpenAM
var fs = require('fs'); // To access file system to read in cert data

console.log("OpenAM Stateless Token Verifier: starting \n");

// Globals --------------------------------------------------------------------------------------------------------------------------------
// For authenticating to OpenAM
var submittedUsername = process.argv[2]; // Pulled in from arg list
var submittedPassword = process.argv[3]; // Pulled in from arg list

// JWT Verification
var pathToSharedSecret = "HMACSharedSecret"; // Used for HMAC signing verification
var pathToPublicKey = "RSAPublicKey"; // Used for RS signing verification and/or decryption
var algorithm = "HS256"; // HS256, HS384, HS512, RS256, RS512, ES256, ES384, ES512, none

var sharedSecret = ""; //Gets populated via file

//OpenAM options
var httpOptions = {
		  hostname: 'openam.example.com',
		  port: 8080,
		  path: '/openam/json/authenticate?realm=stateless',
		  method: 'POST',
		  headers: {
		    'Content-Type': 'application/json',
		    'X-OpenAM-Username' : submittedUsername,
		    'X-OpenAM-Password' : submittedPassword
		  }
	};

var postData = '{}'; // Empty JSON payload for authentication request

// Globals ---------------------------------------------------------------------------------------------------------------------------------

// Check for the correct number of submitted arguments
if (process.argv.length < 4){
		
	console.log("Error! Arguments missing.  Usage: app.js <username> <password> \n");
	return;	
}

// Read in external file that contains HMAC shared secret
fs.readFile(pathToSharedSecret, 'utf8', function (err,data) {
  if (err) {
    return console.log("OpenAM Stateless Token Verifier: error reading shared secret file! \n");
  }
  
  //Pull in shared secret from file and add to global variable for re use
  sharedSecret = data;
  fs.close;
      
});


// Authenticate to OpenAM and get the stateless tokenId value
function authenticate(){

	console.log("OpenAM Stateless Token Verifier: building authentication request for OpenAM \n");
	
	// Create request to authenticate user
	var req = http.request(httpOptions, function(res) {
		  // console.log('STATUS: ' + res.statusCode);
		  // console.log('HEADERS: ' + JSON.stringify(res.headers));
		  res.setEncoding('utf8');
		  res.on('data', function (chunk) {
		    	
			  // console.log(chunk);
			  // Take the chunk response and strip out the important JWT token
			  getJWT(chunk);
			  
		  });
	});

	// Send HTTP request to OpenAM
	req.on('error', function(e) {
		  console.log('OpenAM Stateless Token Verifier: problem with authentication request: ' + e.message);
		});

	// write data to request body
	req.write(postData);
	req.end();	

}


// Utility function to split the OpenAM authentication response into the
// necessary JWT component
function getJWT(response){
	
	    console.log("OpenAM Stateless Token Verifier: authentication response: \n");
	    console.log(response + "\n");
		JWT = JSON.parse(response).tokenId.split('*')[2]; // Pull out tokenId
															// and split off the
															// JWT tail
		console.log("OpenAM Stateless Token Verifier: extracted JWT: \n");
		console.log("Header: " + JWT.split(".")[0] + "\n");
		console.log("Payload: " + JWT.split(".")[1] + "\n");
		console.log("Tail: " + JWT.split(".")[2] + "\n");
		verifyJWT(JWT); // Send JWT to be verified
}

// Verify the tokenId against either the RSA or HMAC algo
function verifyJWT(JWT){

			// If no signing takes place, just do an unverified decode...
			if (algorithm === "none") {
				
				var decoded = jwt.decode(JWT);
				console.log("OpenAM Stateless Token Verifier: unverified decoded JWT: \n");
				console.log(decoded.serialized_session + "\n");
				console.log("OpenAM Stateless Token Verifier: token expiration time: " + new Date(JSON.parse(decoded.serialized_session).expiryTime).toString() + "\n");
	
			} else { // The JWT has been signed...so needs verifying
				
				try {
					var decoded = jwt.verify(JWT,sharedSecret, { algorithms: [algorithm] }, function(error, decoded){
						
						// JWT is valid and has been successfully verified
						if (decoded) {
						
							console.log("OpenAM Stateless Token Verifier: verified and decoded JWT: \n");
							console.log(decoded.serialized_session + "\n");
							console.log("OpenAM Stateless Token Verifier: token expiration time: " + new Date(JSON.parse(decoded.serialized_session).expiryTime).toString() + "\n");
							
						} 
						else { // token can't be verified due to secret being
								// invalid
							
							console.log("OpenAM Stateless Token Verifier: JWT cannot be verified (invalid secret or algorithm) \n");
						}
						
					});
				
				}	catch (error) {
			
					console.log("OpenAM Stateless Token Verifier: error verifying token");
					console.log(error + "\n");
				
				};	
			}
}

// Run through
authenticate();
