import { signJWT } from "./globals";

export default async function sign(body: object, params: string | null, private_key: string) {
    let keys: string[] = [];
    let unsorted_data: { [key: string]: any } = {};

    let params_object: object = {};
    if (params) {
        params_object = Object.fromEntries(new URLSearchParams(params))
    }

    unsorted_data = {
        ...params_object,
        ...body
    };
    keys = Object.keys(unsorted_data).sort();

    let data: { [key: string]: any } = {};
    await keys.forEach((key) => {
        data[key] = unsorted_data[key];
    });

    let jwt = await signJWT(data, private_key);

    return jwt; 
}