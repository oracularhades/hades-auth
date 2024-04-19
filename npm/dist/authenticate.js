import { JSONorForm, VerifyJWT, isNullOrWhiteSpace } from "./globals.js";
import crypto from 'crypto';
async function authenticate(body, params, jwt, public_key, pathname, use_cropped_body) {
    let keys = [];
    let unsorted_data = {};
    let params_object = {};
    if (params.length > 0) {
        params_object = Object.fromEntries(new URLSearchParams(params));
    }
    unsorted_data = {
        ...params_object
    };
    keys = Object.keys(unsorted_data).sort();
    let data = {};
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
    let sha512_authed_checksum = '';
    let body_sha512_authed_checksum = '';
    if (typeof verify_jwt_status === 'string') {
        throw "VerifyJWT output was a string for some reason.";
    }
    else {
        const sha512_authed_checksum_v = verify_jwt_status.checksum.toString();
        sha512_authed_checksum = sha512_authed_checksum_v;
        if (verify_jwt_status.body_checksum) {
            body_sha512_authed_checksum = verify_jwt_status.body_checksum.toString();
        }
        if (use_cropped_body == true) {
            if (!verify_jwt_status.just_file_sha512) {
                throw "use_cropped_body is true - however, jwt.just_file_sha512 is null.";
            }
            body_sha512_authed_checksum = verify_jwt_status.just_file_sha512.toString();
        }
    }
    const hash = crypto.createHash('sha512');
    hash.update(JSON.stringify(data));
    const output_sha512_for_unverified_data = hash.digest('hex');
    // console.log("DATAAA444 sig", JSON.stringify(data));
    if (sha512_authed_checksum != output_sha512_for_unverified_data) {
        // data object does not match checksum in JWT.
        throw "Incoming data does not match checksum in JWT packet.";
    }
    // Ignore the rest of the body and just use the provided field in formdata (not recommended, unless you can't get the full form-data for some reason)
    if (body) {
        if (!body_sha512_authed_checksum) {
            throw "Body was provided - however, jwt.body_checksum is null.";
        }
        const hash = crypto.createHash('sha512');
        const jsonOrFormV = await JSONorForm(body);
        if (jsonOrFormV == "JSON") {
            hash.update(JSON.stringify(body));
        }
        else if (jsonOrFormV != "FormData") {
            hash.update(body);
        }
        const output_sha512_for_unverified_data = hash.digest('hex');
        if (sha512_authed_checksum != output_sha512_for_unverified_data) {
            // data object does not match checksum in JWT.
            throw "Incoming body data does not match checksum in JWT packet.";
        }
    }
    return true;
}
export default authenticate;
