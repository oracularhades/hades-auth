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
    let addon = {
        deviceid: deviceid,
        authenticator_pathname: pathname
    };
    let data_to_be_hashed_for_signing = {
        ...paramsObj,
        ...addon
    };
    let token = null;
    if (properties && properties.body) {
        const jsonOrFormV = await JSONorForm(properties.body);
        jsonOrForm = jsonOrFormV;
    }
    if (properties && properties.body && properties.method && properties.method.toLowerCase() == "post") {
        // Gotta JSON.parse the body. Otherwise it comes out as a string, and the other end reads it as an object.
        let output = properties.body;
        if (jsonOrForm == "JSON") {
            output = JSON.parse(properties.body);
        }
        token = await sign(data_to_be_hashed_for_signing, output, private_key, properties.only_validate_field_in_formdata_for_body);
    }
    else {
        token = await sign(data_to_be_hashed_for_signing, null, private_key, null);
    }
    paramsObj = {
        ...token.metadata,
        authenticator_JWT_Token: token.jwt
    };
    let formDataOutput = new URLSearchParams(paramsObj);
    let outputUrl = `${urlData.origin}${urlData.pathname}`;
    if (formDataOutput.toString() && formDataOutput.toString().length > 0) {
        outputUrl = outputUrl + "?" + formDataOutput.toString();
    }
    return await fetch(outputUrl, properties);
}
