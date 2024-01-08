import jwt, { JwtPayload } from 'jsonwebtoken';
import { SignJWT, importPKCS8, JWTPayload } from "jose";

function isNullOrWhiteSpace(str: string | null | undefined): boolean {
    if (str === null || str === undefined) {
        return true;
    }
  
    if (str === 'null' || str === 'undefined') {
        return true;
    }
  
    if (str.trim().length === 0) {
        return true;
    }
  
    return false;
}

function generateRandomID() {
    let random_string: String = '';
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (let i: number = 0; i < characters.length; i++){
        random_string += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return random_string.slice(0, 20)+new Date().getTime();
}

function importEllipticPublicKey(pem: string) {
    if (!pem.startsWith("-----BEGIN PUBLIC KEY-----")) {
        pem = "-----BEGIN PUBLIC KEY-----"+pem;
    }
    if (!pem.endsWith("-----END PUBLIC KEY-----")) {
        pem = pem+"-----END PUBLIC KEY-----";
    }
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pem_contents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    const binaryDerString = atob(pem_contents);
    const binaryDer = str2ab(binaryDerString);
  
    return crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "ECDSA",
            namedCurve: "P-521",
        },
        true,
        ["verify"]
    );
}
  
function importEllipticPrivateKey(pem: string) {
    if (!pem.startsWith("-----BEGIN PRIVATE KEY-----")) {
        pem = "-----BEGIN PRIVATE KEY-----"+pem;
    }
    if (!pem.endsWith("-----END PRIVATE KEY-----")) {
        pem = pem+"-----END PRIVATE KEY-----";
    }
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pem_contents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    const binaryDerString = atob(pem_contents);
    const binaryDer = str2ab(binaryDerString);
  
    return crypto.subtle.importKey(
        "pkcs8",
        binaryDer,
        {
            name: "ECDSA",
            hash: "SHA-256",
            namedCurve: "P-521"
        },
        true,
        ["sign"]
    );
}

function str2ab(str: string) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

async function VerifyJWT(jwt_string: string, public_key: string): Promise<string | JwtPayload> {
    if (isNullOrWhiteSpace(jwt_string)) {
        throw "jwt is null.";
    }
    if (isNullOrWhiteSpace(public_key)) {
        throw "public_key is null or whitespace";
    }

    const publicKeyPem = '-----BEGIN PUBLIC KEY-----\n' +
`${public_key}\n` +
'-----END PUBLIC KEY-----\n';
  
    const decoded_data: string | JwtPayload = await jwt.verify(jwt_string, publicKeyPem);
  
    return decoded_data;
}

async function signJWT(data: JWTPayload, privateKeyV: string) {
    const options = {
        algorithm: 'ES512',
        compact: true,
        fields: { typ: 'JWT' }
    };

    const privateKeyPem = '-----BEGIN PRIVATE KEY-----\n' +
`${privateKeyV.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")}\n` +
'-----END PRIVATE KEY-----\n';

    const privateKey = await importPKCS8(privateKeyPem, "ES512");

    const jwt = await new SignJWT(data) // ECDSA with P-521 curve
    .setProtectedHeader({ alg: 'ES512' }) // Optional if you want to specify headers
    .sign(privateKey);
    
    return jwt;
}

async function JSONorForm(variable: any) {
    if (variable instanceof FormData) {
        return 'FormData';
    }

    // Check if it's JSON
    try {
        JSON.parse(JSON.stringify(variable));
        return 'JSON';
    } catch (error) {
    }
    
    return null;
}

async function get_file_binary(file: any): Promise<string> {
    return new Promise((resolve, reject) => {
        // if (typeof window === 'undefined' && typeof process === 'object') { // Check if running in Node.js
            const data = file instanceof Buffer ? file.toString('binary') : file;
            resolve(data);
        // } else {
        //     reject(new Error('FileReader is not supported in this environment.'));
        // }
    });
}

export { isNullOrWhiteSpace, generateRandomID, importEllipticPublicKey, importEllipticPrivateKey, signJWT, VerifyJWT, JSONorForm, get_file_binary }