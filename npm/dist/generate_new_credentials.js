function ab2str(buf) {
    const uintArray = new Uint8Array(buf);
    const regularArray = Array.from(uintArray);
    return String.fromCharCode.apply(null, regularArray);
}
export default async function generate_new_credentials() {
    const keyPair = await crypto.subtle.generateKey({
        name: "ECDSA",
        namedCurve: "P-521",
    }, true, ["sign", "verify"]);
    const publicexported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicexportedAsString = ab2str(publicexported);
    const publicexportedAsBase64 = btoa(publicexportedAsString);
    const privateexported = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    const privateexportedAsString = ab2str(privateexported);
    const privateexportedAsBase64 = btoa(privateexportedAsString);
    return {
        public_key: `-----BEGIN PUBLIC KEY-----
${publicexportedAsBase64}
-----END PUBLIC KEY-----`,
        private_key: `-----BEGIN PRIVATE KEY-----
${privateexportedAsBase64}
-----END PRIVATE KEY-----`
    };
}
