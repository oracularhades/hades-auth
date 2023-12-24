import { VerifyJWT, isNullOrWhiteSpace } from "./globals";
import crypto from 'crypto';

async function authenticate(body: object, params: string, jwt: string, public_key: string, pathname: string, filebuffer: string) {
    // if (filebuffer) {
    //     let obj = req.body;
    //     if (!obj || !obj.signed_auth_object) {
    //         throw "Your request is formdata and missing body.signed_auth_object";
    //     }

    //     let signed_auth_object = null;
    //     try {
    //         signed_auth_object = JSON.parse(req.body.signed_auth_object);
    //     } catch {
    //         throw "signed_auth_object is not an object.";
    //     }

    //     const hashData = new TextEncoder().encode(Buffer.from(filebuffer));
    //     const hashBuffer = await crypto.subtle.digest("SHA-256", hashData);
    //     const hashArray = Array.from(new Uint8Array(hashBuffer));
    //     const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

    //     if (hashHex != signed_auth_object.hash) {
    //         console.log("DOESN'T MATCH", hashHex, signed_auth_object.hash);
    //         throw "Hash in signed_auth_object and hash for provided formdata file does not match. (Your hash should be in hex)";
    //     }
    // }

    let keys: string[] = [];
    let unsorted_data: { [key: string]: any } = {};

    let params_object: object = Object.fromEntries(new URLSearchParams(params));

    unsorted_data = {
        ...params_object,
        ...body
    };
    keys = Object.keys(unsorted_data).sort();

    let data: { [key: string]: any } = {};
    await keys.forEach((key) => {
        if (key != "authenticator_metadata" && key != "authenticator_JWT_Token") {
            data[key] = unsorted_data[key];
        }
    });
    
    // Make sure deviceid and JWT_Token are specified.
    if (isNullOrWhiteSpace(jwt)) {
        throw "JWT is null or whitespace.";
    }
  
    // Check the pathname inside the signed-object, it needs to match the current pathname, this makes it more annoying for attackers to re-play signed packets. Such as if 2 API endpoints use similar properties, it's locked to the API endpoint is was signed for.
    const data_pathname = data.pathname;
    if (isNullOrWhiteSpace(data_pathname)) {
        throw "signedObject.pathname is null or whitespace.";
    }
    if (data_pathname != pathname) {
        throw `Signed URL is "${data_pathname}" and does not match "${pathname}"`;
    }
  
    const verify_jwt_status = await VerifyJWT(jwt, public_key); // an error will throw here if the request is unauthorized.

    let sha512_authed_checksum: string = '';
    if (typeof verify_jwt_status === 'string') {
        throw "VerifyJWT output was a string for some reason.";
    } else {
        const sha512_authed_checksum_v: string = verify_jwt_status.checksum.toString();
        sha512_authed_checksum = sha512_authed_checksum_v;
    }

    const hash = crypto.createHash('sha512');
    hash.update(JSON.stringify(data));
    const output_sha512_for_unverified_data: string = hash.digest('hex');

    if (sha512_authed_checksum != output_sha512_for_unverified_data) {
        // data object does not match checksum in JWT.
        throw "Incoming data does not match checksum in JWT packet.";
    }

    return true;
}

export default authenticate;