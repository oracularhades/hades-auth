import { VerifyJWT } from "../globals.js";

export default async function verify_static_auth(jwt: string, deviceid: string, public_key: string, expiry: number) {
    // 2592000000 (if a default expiry is setup in the future, this is the milliseconds for 30 days)

    try {
        JSON.parse(jwt);
    } catch (error) {
        // auth_generation is not valid JSON.
        throw "JWT payload is not valid JSON";
    }

    const jwt_data = JSON.parse(jwt);
    if (!jwt_data) {
        throw "JWT payload is missing.";
    }
    if (!jwt_data.deviceid) {
        throw "jwt.deviceid is missing.";
    }
    if (jwt_data.created !> 0) {
        throw "jwt.created must be above 0";
    }

    let date1 = jwt_data.created;
    let date2 = new Date().getTime();
    if (date2 < date1) {
        throw "jwt.created is before current date."
    }
    let diff = date2 - date1;
    if (!diff && diff != 0) {
        throw "Invalid date.";
    }
    if (diff >= expiry) {
        throw "JWT is expired.";
    }

    if (jwt_data.deviceid != deviceid) {
        throw "jwt.deviceid and provided deviceid do not match.";
    }

    return await VerifyJWT(jwt, public_key); // This will throw an error if invalid.
}