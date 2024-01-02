import { VerifyJWT, get_file_binary, isNullOrWhiteSpace } from "./globals.js";
import crypto from 'crypto';

async function authenticate(body: object, params: string, jwt: string, public_key: string, pathname: string, filebuffer: string) {
    let keys: string[] = [];
    let unsorted_data: { [key: string]: any } = {};

    let params_object: object = {};
    if (params.length > 0) {
        params_object = Object.fromEntries(new URLSearchParams(params));
    }

    unsorted_data = {
        ...params_object
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
    const data_pathname = data.authenticator_pathname;
    if (!isNullOrWhiteSpace(data_pathname)) {
        if (data_pathname != pathname) {
            throw `Signed URL is "${data_pathname}" and does not match "${pathname}"`;
        }
    }
  
    const verify_jwt_status = await VerifyJWT(jwt, public_key); // an error will throw here if the request is unauthorized.

    let sha512_authed_checksum: string = '';
    let body_sha512_authed_checksum: string = '';
    if (typeof verify_jwt_status === 'string') {
        throw "VerifyJWT output was a string for some reason.";
    } else {
        const sha512_authed_checksum_v: string = verify_jwt_status.checksum.toString();
        sha512_authed_checksum = sha512_authed_checksum_v;

        if (verify_jwt_status.body_checksum) {
            const body_sha512_authed_checksum_v: string = verify_jwt_status.body_checksum.toString();
            body_sha512_authed_checksum = body_sha512_authed_checksum_v;
        }
    }

    console.log("DATAAA444", JSON.stringify(data));

    const hash = crypto.createHash('sha512');
    hash.update(JSON.stringify(data));
    const output_sha512_for_unverified_data: string = hash.digest('hex');
    // console.log("DATAAA444 sig", JSON.stringify(data));
    if (sha512_authed_checksum != output_sha512_for_unverified_data) {
        // data object does not match checksum in JWT.
        throw "Incoming data does not match checksum in JWT packet.";
    }

    console.log(body);

    if (body && Object.keys(body).length > 0) {
        if (!body_sha512_authed_checksum) {
            throw "Body was provided, however, jwt.body_checksum is not specified.";
        }
    
        const hashData = new TextEncoder().encode(await get_file_binary(body));
        const hashBuffer = await crypto.subtle.digest("SHA-512", hashData);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

        if (body_sha512_authed_checksum != hashHex) {
            // body does not match checksum in JWT.
            throw "Incoming body data does not match checksum in JWT packet.";
        }
    }

    return true;
}

export default authenticate;