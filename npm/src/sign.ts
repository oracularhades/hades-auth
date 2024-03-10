import { JSONorForm, get_formdata_field_hash, signJWT } from "./globals.js";
import crypto from 'crypto';

export default async function sign(metadata: object, body: any, private_key: string, only_use_field_for_body: string | null) {
    let keys: string[] = [];
    let unsorted_data: { [key: string]: any } = {};

    unsorted_data = {
        ...metadata
    };

    if (body) {
        let hashHex = null;
        let hashHex_file = null;

        const hashData = new TextEncoder().encode(body);
        let hashBuffer = null;
        if (typeof window === 'undefined' && typeof process === 'object') {
            hashBuffer = await crypto.subtle.digest("SHA-512", hashData);
        } else if (typeof window !== 'undefined') {
            hashBuffer = hashBuffer = await window.crypto.subtle.digest("SHA-512", hashData);
        } else {
            throw 'FileReader is not supported in this environment.';
        }
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

        const jsonOrFormV = await JSONorForm(body);
        if (jsonOrFormV == "FormData" && only_use_field_for_body) {
            hashHex_file = await get_formdata_field_hash(only_use_field_for_body, body);
        }

        unsorted_data = {
            ...unsorted_data,
            body_sha512: hashHex,
        }
        
        if (only_use_field_for_body) {
            unsorted_data = {
                ...unsorted_data,
                // just_file_sha512: hashHex_file // doesn't look like this is needed.
            }
        }
    }
    keys = Object.keys(unsorted_data).sort();

    let data: { [key: string]: any } = {};
    await keys.forEach((key) => {
        data[key] = unsorted_data[key];
    });

    console.log("METADATA", JSON.stringify(data));

    const hash = crypto.createHash('sha512');
    hash.update(JSON.stringify(data));
    const output_sha512_checksum: string = hash.digest('hex');

    let jwt_data = {
        checksum: output_sha512_checksum,
        exp: new Date().getTime()+60000,
        body_checksum: data.body_sha512,
        just_file_sha512: data.just_file_sha512
    }

    let jwt = await signJWT(jwt_data, private_key);

    return { metadata: data, body: body, jwt: jwt }; 
}