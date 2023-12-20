import { VerifyJWT, isNullOrWhiteSpace } from "./globals";

async function authenticate(jwt: string, public_key: string, deviceid: string, pathname: string, filebuffer: string) {
    // Initial value checks.
    if (!pathname) {
        throw "pathname is null or whitespace.";
    }
  
    if (filebuffer) {
        let obj = req.body;
        if (!obj || !obj.signed_auth_object) {
            throw "Your request is formdata and missing body.signed_auth_object";
        }

        let signed_auth_object = null;
        try {
            signed_auth_object = JSON.parse(req.body.signed_auth_object);
        } catch {
            throw "signed_auth_object is not an object.";
        }

        const hashData = new TextEncoder().encode(Buffer.from(filebuffer));
        const hashBuffer = await crypto.subtle.digest("SHA-256", hashData);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

        if (hashHex != signed_auth_object.hash) {
            console.log("DOESN'T MATCH", hashHex, signed_auth_object.hash);
            throw "Hash in signed_auth_object and hash for provided formdata file does not match. (Your hash should be in hex)";
        }
    }
    
    // Make sure deviceid and JWT_Token are specified.
    if (isNullOrWhiteSpace(deviceid)) {
        throw "deviceid is null or whitespace.";
    }
    if (isNullOrWhiteSpace(jwt)) {
        throw "jwt is null or whitespace.";
    }
  
    // Check the pathname inside the signed-object, it needs to match the current pathname, this makes it more annoying for attackers to re-play signed packets. Such as if 2 API endpoints use similar properties, it's locked to the API endpoint is was signed for.
    const data_pathname = data.pathname;
    if (isNullOrWhiteSpace(data_pathname)) {
        throw "signedObject.pathname is null or whitespace.";
    }
    if (data_pathname != pathname) {
        throw `Signed URL is "${data_pathname}" and does not match "${pathname}"`;
    }
  
    const accountid = await VerifyJWT(jwt, public_key); // an error will throw here if the request is unauthorized.
    
    return { successful: true, response: null, accountid: accountid, deviceid: deviceid };
}

export default authenticate;