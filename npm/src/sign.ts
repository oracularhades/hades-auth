import { get_file_binary, signJWT } from "./globals.js";
import crypto from 'crypto';

export default async function sign(metadata: object, body: object | null, private_key: string) {
    let keys: string[] = [];
    let unsorted_data: { [key: string]: any } = {};

    unsorted_data = {
        ...metadata
        // ...body // body is no longer included here, has it's own checksum. Unsorted_data is just for metadata and params now.
    };

    let hashHex = null;
    if (body && Object.keys(body).length > 0) {
        const hashData = new TextEncoder().encode(await get_file_binary(body));
        const hashBuffer = await crypto.subtle.digest("SHA-512", hashData);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

        unsorted_data = {
            ...unsorted_data,
            body_sha512: hashHex
        }
    }
    keys = Object.keys(unsorted_data).sort();

    let data: { [key: string]: any } = {};
    await keys.forEach((key) => {
        data[key] = unsorted_data[key];
    });

    console.log("SIGN", JSON.stringify(data));

    const hash = crypto.createHash('sha512');
    hash.update(JSON.stringify(data));
    const output_sha512_checksum: string = hash.digest('hex');

    let jwt_data = {
        checksum: output_sha512_checksum,
        body_checksum: data.body_sha512
    }

    let jwt = await signJWT(jwt_data, private_key);

    return { metadata: data, body: body, jwt: jwt }; 
}