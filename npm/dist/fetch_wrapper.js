import { JSONorForm } from "./globals.js";
import sign from "./sign.js";
export default async function fetch_wrapper(url, properties, deviceid, private_key) {
    if (!url) {
        throw `url is ${url}`;
    }
    let urlData = new URL(url);
    const pathname = urlData.pathname;
    const searchParams = urlData.searchParams;
    // Convert the search parameters to an object
    let paramsObj = {};
    for (const [key, value] of searchParams.entries()) {
        paramsObj[key] = value;
    }
    let jsonOrForm = null;
    // Logic for if the method is a POST request.
    if (properties && properties.body && properties.method && properties.method.toLowerCase() == "post") {
        const jsonOrFormV = await JSONorForm(properties.body);
        jsonOrForm = jsonOrFormV;
        if (jsonOrForm == "JSON") {
            const body = JSON.parse(properties.body);
            properties.headers = {
                ...properties.headers,
                "Content-Type": "application/json"
            };
            properties.body = body;
        }
        else if (jsonOrForm == "FormData") {
            throw "Cannot do formdata right now.";
            // const hashData = new TextEncoder().encode(Buffer.from(await internal().getFileBinary(await properties.body.get("file"))));
            // const hashBuffer = await crypto.subtle.digest("SHA-256", hashData);
            // const hashArray = Array.from(new Uint8Array(hashBuffer));
            // const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
            // signed_auth_object = JSON.stringify({
            //     hash: hashHex
            // })
        }
    }
    let addon = {
        deviceid: deviceid,
        authenticator_pathname: pathname
    };
    let data_to_be_hashed_for_signing = {
        ...paramsObj,
        ...addon
    };
    if (properties.body) {
        data_to_be_hashed_for_signing = {
            ...data_to_be_hashed_for_signing,
            ...properties.body
        };
    }
    const token = await sign(data_to_be_hashed_for_signing, new URLSearchParams(paramsObj).toString(), private_key);
    if (properties.method == "POST") {
        properties.body = JSON.stringify({
            ...properties.body,
            ...addon,
            authenticator_JWT_Token: token
        });
    }
    else {
        paramsObj = {
            ...paramsObj,
            ...addon,
            authenticator_JWT_Token: token
        };
    }
    let formDataOutput = new URLSearchParams(paramsObj);
    let outputUrl = `${urlData.origin}${urlData.pathname}`;
    if (formDataOutput.toString() && formDataOutput.toString().length > 0) {
        outputUrl = outputUrl + "?" + formDataOutput.toString();
    }
    return await fetch(outputUrl, properties);
}
