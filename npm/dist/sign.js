import { signJWT } from "./globals.js";
import crypto from 'crypto';
export default async function sign(body, params, private_key) {
    let keys = [];
    let unsorted_data = {};
    let params_object = {};
    if (params && params.length > 0) {
        params_object = Object.fromEntries(new URLSearchParams(params));
    }
    unsorted_data = {
        ...params_object,
        ...body
    };
    keys = Object.keys(unsorted_data).sort();
    let data = {};
    await keys.forEach((key) => {
        data[key] = unsorted_data[key];
    });
    const hash = crypto.createHash('sha512');
    hash.update(JSON.stringify(data));
    const output_sha512_checksum = hash.digest('hex');
    console.log("OUTPUT CHECKSUM", output_sha512_checksum, "OUTPUT DATA", JSON.stringify(data));
    data = {
        checksum: output_sha512_checksum
    };
    let jwt = await signJWT(data, private_key);
    return jwt;
}
