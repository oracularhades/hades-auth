import { generateRandomID, importEllipticPublicKey, isNullOrWhiteSpace } from "./globals.js";
export default async function onboard_new_device(public_key) {
    if (isNullOrWhiteSpace(public_key)) {
        throw `public_key is null or whitespace.`;
    }
    const deviceid = await generateRandomID();
    const publickeyimport = await importEllipticPublicKey(`-----BEGIN PUBLIC KEY-----
${public_key}
-----END PUBLIC KEY-----`);
    if (publickeyimport.usages[0] != "verify" || publickeyimport.usages.length != 1) {
        throw 'Public key usages array must be ["sign", "verify"]';
    }
    if (!publickeyimport.algorithm || publickeyimport.algorithm.name != "ECDSA") {
        throw "Algorithm name must be ECDSA";
    }
    // if (!publickeyimport.algorithm || publickeyimport.algorithm.namedCurve != "P-521") {
    //     throw "namedCurve must be P-521.";
    // }
    if (publickeyimport.type != "public") {
        throw "Key type MUST be public key. It is extremely insecure to surrender your private authentication key. You should consider the provided RSA key compromised, please generate a new key.";
    }
    return { ok: true, deviceid: deviceid };
}
