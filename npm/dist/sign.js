import { JSONorForm, get_formdata_field_hash, signJWT } from "./globals.js";
import crypto from 'crypto';
export default async function sign(metadata, body, private_key, only_use_field_for_body) {
    let keys = [];
    let unsorted_data = {};
    unsorted_data = {
        ...metadata
    };
    if (body) {
        let hashHex = null;
        let hashHex_file = null;
        const jsonOrFormV = await JSONorForm(body);
        const hash = crypto.createHash('sha512');
        if (jsonOrFormV == "JSON") {
            hash.update(JSON.stringify(body));
        }
        else if (jsonOrFormV != "FormData") {
            hash.update(body);
        }
        const body_output_sha512_checksum = hash.digest('hex');
        hashHex = body_output_sha512_checksum;
        if (jsonOrFormV == "FormData" && only_use_field_for_body) {
            hashHex_file = await get_formdata_field_hash(only_use_field_for_body, body);
        }
        unsorted_data = {
            ...unsorted_data,
            body_sha512: hashHex,
        };
        if (only_use_field_for_body) {
            unsorted_data = {
                ...unsorted_data,
                // just_file_sha512: hashHex_file // doesn't look like this is needed.
            };
        }
    }
    keys = Object.keys(unsorted_data).sort();
    let data = {};
    await keys.forEach((key) => {
        data[key] = unsorted_data[key];
    });

    const hash = crypto.createHash('sha512');
    hash.update(JSON.stringify(data));
    const output_sha512_checksum = hash.digest('hex');
    let jwt_data = {
        checksum: output_sha512_checksum,
        exp: new Date().getTime() + 31536000000,
        body_checksum: data.body_sha512,
        just_file_sha512: data.just_file_sha512
    };
    let jwt = await signJWT(jwt_data, private_key);
    return { metadata: data, body: body, jwt: jwt };
}
