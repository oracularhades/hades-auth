# About
Authentication libraries are typically very messy. Usually they're terrible to start off with, too cramped and don't solve a problem enough to be worth using. Most developers resort to session keys / bearer tokens because it's the easiest. This library aims to change that by making public / private key signing authentication easier than session / bearer tokens.

**Why should I be using public/private key signing for authentication?**
Session keys / bearer tokens are weak because if someone intercepts them, they can use them. With public / private key signing and correct implementation, if someone were to intercept your request, they would only to be able to resend the request you just signed (and that can be stopped with nonces and signing) and can't use the authentication for whatever they want. With session / bearer tokens, if someone intercepts your request, they can take that token and use it to the full extent it's authorized.

If your database is leaked, with session keys / bearer tokens, it comes down to your hashing methods and handling of that data in your database, including if someone had gotten into a webserver/load-balancer and started collecting tokens. With public / private key signing, you're only storing public-keys on your end and they're called "public-keys" for a reason, because it doesn't matter if they're leaked.

# Generate credentials (client-side)
```
import { generate_new_credentials } from "hades-auth";

const credentials = await generate_new_credentials();

// credentials.private_key - Store this locally and **NEVER** allow it to leave the device. Avoid storing it in cookies, because cookies, in some configurations, are sent to the server by your browser, and you need to make sure that doesn't happen.

// credentials.public_key - Send this to the server, it's public, and it doesn't matter if this is leaked. That's why public/private key authentication is so amazing. If you're database is leaked, provided the attacker didn't modify anything, your logged-in devices don't need to be reset.
```

# Verify the credentials are up to standard (server-side)
```
import { onboard_new_device } from "hades-auth";

// Webserver logic here, such as taking a POST request with the public-key.
try {
    const verification = await onboard_new_device(body.public_key);
    
    // verification.deviceid - for your convenience, a deviceid is generated by Authenticator, however, you can easily disregard it and use your own identifier.
} catch (error) {
    console.log("Invalid", error);
    
    // Respond to the client with an error message that their key is not up to standard.
}

// Add logic for storing the public-key in your database, and respond to the client with 200 status and a deviceid you can use in the future to match it with the stored public-key.
```

# Use fetch_wrapper to seamlessly sign requests (client-side)
```
import { fetch_wrapper } from "hades-auth";

let device_id = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Normally you'd get this from local storage or elsewhere.
let private_key = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAvH5WytTrfNHtfmJ0heMDotHBQXFR7jYx1rAZYpa0fNJcDeYIMV+mUjM/9ujMK4aaqwaxN1Viw2Ku/zlfKCJj3O2hgYkDgYYABADAKAtlhXvMXArHWxDt3IrUoVFndTyCjiSyteJwSVvd5VLr1hXVTZ9VJHOpSxq+Ght2LWaqIBShQfT4th/vzroypgBNSnkf+dH1bqiSaT01tznAoKwSqfxBgdRspJxCmYd87ukf/KB/INrZ7XX+4/pAT9Q8NqQEctS/DHrg/dRIUyEmNg==
-----END PRIVATE KEY-----`;

// pstttt, if you're using expressjs with JSON parsing middleware, you need to set "Content-Type" to be "application/json" when sending JSON, otherwise it errors and thinks there is an empty body. A little annoying quirk of expressjs.
const response = fetch_wrapper(`https://example.com`, {
    method: 'POST',
    mode: 'cors',
    cache: 'default',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        name: "John Doe"
    }),
    redirect: 'error',
}, device_id, private_key)
```

# Sign data (client-side)
```
import { sign } from "hades-auth";

let metadata = {
    deviceid: ''
    // whatever you want here!
}

// You should think of metadata like URL params and the body object as well...a body. They're seperate because metadata is _always_ json, which makes it easy to pass something like an image in the body and not need to mold additional data like the deviceid into that formdata. They're seperate because data formatting can get quite messy and it's absolutely better to have the 2 seperate values. Here are some example bodies, but you can use what you want!

let formData = new FormData();
formData.set("a", "1");
formData.set("b", "2");
formData.set("c", "3");
let body = formData.toString();

let body1 = {
    a: "1",
    b: "2",
    c: "3"
}

let body3 = "SSB3YW50ZWQgdG8gcHV0IGFuIGltYWdlIG9yIGEgcXVvdGUgaGVyZSwgYnV0IGJvdGggc3RyaW5ncyB3b3VsZCBoYXZlIGJlZW4gdG9vIGxvbmcuIEFueXdheSwgbmljZSB0byBzZWUgeW91J3JlIGVuam95aW5nIHRoZSBjb2RlYmFzZSBlbm91Z2ggdG8gcGVhayBiZWhpbmQgdGhlIGN1cnRhaW4gOik=";

// Normally you'd get this from local storage or elsewhere.
let private_key = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAvH5WytTrfNHtfmJ0heMDotHBQXFR7jYx1rAZYpa0fNJcDeYIMV+mUjM/9ujMK4aaqwaxN1Viw2Ku/zlfKCJj3O2hgYkDgYYABADAKAtlhXvMXArHWxDt3IrUoVFndTyCjiSyteJwSVvd5VLr1hXVTZ9VJHOpSxq+Ght2LWaqIBShQfT4th/vzroypgBNSnkf+dH1bqiSaT01tznAoKwSqfxBgdRspJxCmYd87ukf/KB/INrZ7XX+4/pAT9Q8NqQEctS/DHrg/dRIUyEmNg==
-----END PRIVATE KEY-----`;

const jwt = await sign(metadata, body, private_key);

// Send this JWT to your server.
```

# Authenticate data (server-side)
```
import { authenticate } from "hades-auth";

let body = // get incoming body from your webserver as an object (not a JSON string).
let params = new URLSearchParams(); // Don't panic about params! If you're not planning on sending data in traditional means, such as an HTTPS request, you can leave this as an empty string and just use the body param.

// Normally you'd get this from local storage or elsewhere.
let private_key = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAvH5WytTrfNHtfmJ0heMDotHBQXFR7jYx1rAZYpa0fNJcDeYIMV+mUjM/9ujMK4aaqwaxN1Viw2Ku/zlfKCJj3O2hgYkDgYYABADAKAtlhXvMXArHWxDt3IrUoVFndTyCjiSyteJwSVvd5VLr1hXVTZ9VJHOpSxq+Ght2LWaqIBShQfT4th/vzroypgBNSnkf+dH1bqiSaT01tznAoKwSqfxBgdRspJxCmYd87ukf/KB/INrZ7XX+4/pAT9Q8NqQEctS/DHrg/dRIUyEmNg==
-----END PRIVATE KEY-----`;
let pathname = // get pathname from your webserver. Hint: If you're using expressjs, it's req.path :)

// body: the incoming body of your request, as an object (not a json string).
// params: incoming URL params, formatted as a params string, such as "?a=1&b=2&c=3";
// jwt: jwt generated from fetch-wrapper() or sign(). If you used fetch_wrapper, in POST requests you can find it in your request body with the key "authenticator_JWT_Token", and for everything else as a param with the key "authenticator_JWT_Token".
// pathname: The pathname of the incoming request. Fetch_wrapper signs the request pathname (and if you're using sign(), you should also be adding a body.authenticator_pathname or params.authenticator_pathname key) and you'll need to specify the pathname for authentication to be successful.

try {
    const authentication = await authenticate(body, params.toString(), jwt, public_key, pathname); // returns true if successful.
} catch (error) {
    // Authentication failed.
}
```
