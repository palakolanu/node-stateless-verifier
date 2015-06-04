<b>Node Stateless Verifier</b>
</br>
</br>
A basic JSON Web Token (JWT) verifier and decoder, designed specifially for use with ForgeRock's stateless token model within OpenAM.
<br/>
</br>
The concept is to allow 'offline' authentication and authorization of the issued token to allow for local authorization decision making
<br/>
<br/>
<b>Installation</b>
<br/>
This app is written in node.js, so node.js will need to be download and configured for your operating system. Once installed, clone 
the node-stateless-verifier project locally.  Run "node install" from within this project directory to install dependencies
 from the package.json file.
<br/>
<b>Usage</b>
<br/>
Edit the necessary app.js global variables, for the specific OpenAM deployment you want to run against.
This includes the server, port, URI and so on.  Also add in any specifics around the signing and encryption algorithms used.
Enter any HMAC shared secrets or public keys in the necessary files (sharedSecret or publicKey) in the node-stateless-verifier directory.
<br/>
<br/>
To run enter <b>node app.js <username> <password></b>
<br/>
The username and password refer to a user that is able to authenticate against the appropriate pre-configured stateless realm within OpenAM.
<br/>
This will authenticate to the necessary OpenAM realm that is configured for stateless token management.  The stateless tokenId is captured
and verified, based on the algorithm and shared secret/public key settings within the app.js file.
<br/>
Note - tested against OpenAM 13.0 (nightly build)
