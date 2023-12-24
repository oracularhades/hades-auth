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
    let signed_auth_object = {};
    // Logic for if the method is a POST request.
    if (properties && properties.method && properties.method.toLowerCase() == "post") {
        const jsonOrFormV = await JSONorForm(properties.body);
        jsonOrForm = jsonOrFormV;
        if (jsonOrForm == "JSON") {
            const body = JSON.parse(properties.body);
            let bodyObject = {
                ...body,
                pathname: pathname
            };
            properties.headers = {
                ...properties.headers,
                "Content-Type": "application/json"
            };
            properties.body = JSON.stringify(bodyObject);
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
        else {
            // I don't think this is needed?
            let bodyObject = {
                pathname: pathname
            };
            properties.headers = {
                ...properties.headers,
                "Content-Type": "application/json"
            };
            properties.body = JSON.stringify(bodyObject);
        }
    }
    let data_to_be_hashed_for_signing = {
        ...paramsObj,
        deviceid: deviceid,
        pathname: pathname
    };
    const token = await sign(data_to_be_hashed_for_signing, new URLSearchParams(paramsObj).toString(), private_key);
    if (properties.method == "POST") {
        properties.body = {
            ...properties.body,
            authenticator_JWT_Token: token
        };
    }
    else {
        paramsObj = {
            ...paramsObj,
            authenticator_JWT_Token: token,
            deviceid: deviceid,
            pathname: pathname
        };
    }
    let formDataOutput = new URLSearchParams(paramsObj);
    let outputUrl = `${urlData.origin}${urlData.pathname}`;
    if (formDataOutput.toString() && formDataOutput.toString().length > 0) {
        outputUrl = outputUrl + "?" + formDataOutput.toString();
    }
    return await fetch(outputUrl, properties);
}
