import sign from "../sign.js";
export default async function sign_static_auth(deviceid, private_key, additional_metadata) {
    const data = {
        deviceid: deviceid,
        created: new Date().getTime(),
        additional_metadata: additional_metadata
    };
    let sign_status = await sign(data, null, private_key, null);
    return sign_status.jwt;
}
