import { JSONorForm } from "./globals";

export default async function fetch_wrapper(url: string, properties: any, deviceid: string, private_key: string, react_native_compatability: boolean) {
    if (!url) {
        throw `url is ${url}`;
    }

    let urlData = null;
    if (react_native_compatability == true) {
        const { URL: React_Url, URLSearchParams: React_URLSearchParams } = require("react-native-url-polyfill");
        urlData = new React_Url(url);
    } else {
        urlData = new URL(url);
    }
    
    const pathname = urlData.pathname;
    const searchParams = urlData.searchParams;
    // Convert the search parameters to an object
    let paramsObj: { [key: string]: any } = {};
    for (const [key, value] of searchParams.entries()) {
        paramsObj[key] = value;
    }

    const options = {
        algorithm: 'ES512',
        compact: true,
        fields: { typ: 'JWT' }
    };

    if (properties) {
        paramsObj = {
            ...paramsObj,
            pathname: pathname
        }

        paramsObj.deviceid = deviceid;
    }

    let jsonOrForm = null;
    let signed_auth_object = {};

    if (properties && properties.method && properties.method.toLowerCase() == "post") {
        const jsonOrFormV = await JSONorForm(properties.body);

        jsonOrForm = jsonOrFormV;

        if (jsonOrForm == "JSON") {
            const body = JSON.parse(properties.body);
            let bodyObject = {
                ...body,
                pathname: pathname,
            };

            properties.headers = {
                ...properties.headers,
                "Content-Type": "application/json"
            }
            properties.body = JSON.stringify(bodyObject);
        } else if (jsonOrForm == "FormData") {
            throw "Cannot do formdata right now.";
            // const hashData = new TextEncoder().encode(Buffer.from(await internal().getFileBinary(await properties.body.get("file"))));
            // const hashBuffer = await crypto.subtle.digest("SHA-256", hashData);
            // const hashArray = Array.from(new Uint8Array(hashBuffer));
            // const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

            // signed_auth_object = JSON.stringify({
            //     hash: hashHex
            // })
        } else {
            // I don't think this is needed?
            let bodyObject = {
                pathname: pathname,
            };

            properties.headers = {
                ...properties.headers,
                "Content-Type": "application/json"
            }
            properties.body = JSON.stringify(bodyObject);
        }
    }

    let signatureInputObject = {
        ...paramsObj,
    }

    if (jsonOrForm == "FormData") {
        signatureInputObject = {
            ...signatureInputObject,
            signed_auth_object: signed_auth_object
        }

        properties.body.append("signed_auth_object", signed_auth_object);
    } else if (properties.body && typeof properties.body == "string") {
        signatureInputObject = {
            ...signatureInputObject,
            ...JSON.parse(properties.body)
        }
    }

    const token = await general().signJWT(await general().sortedObject(signatureInputObject), private_key, options);
    paramsObj.JWT_Token = token;

    let formDataOutput = new URLSearchParams(paramsObj);

    let outputUrl = `${urlData.origin}${urlData.pathname}`;
    if (formDataOutput.toString() && formDataOutput.toString().length > 0) {
        outputUrl = outputUrl+"?"+formDataOutput.toString();
    }

    return await fetch(outputUrl, properties);
}