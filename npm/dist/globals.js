"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JSONorForm = exports.VerifyJWT = exports.signJWT = exports.importEllipticPrivateKey = exports.importEllipticPublicKey = exports.generateRandomID = exports.isNullOrWhiteSpace = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const jose_1 = require("jose");
function isNullOrWhiteSpace(str) {
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
exports.isNullOrWhiteSpace = isNullOrWhiteSpace;
function generateRandomID() {
    let random_string = '';
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
    for (let i = 0; i < characters.length; i++) {
        random_string += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return random_string.slice(0, 20) + new Date().getTime();
}
exports.generateRandomID = generateRandomID;
function importEllipticPublicKey(pem) {
    if (!pem.startsWith("-----BEGIN PUBLIC KEY-----")) {
        pem = "-----BEGIN PUBLIC KEY-----" + pem;
    }
    if (!pem.endsWith("-----END PUBLIC KEY-----")) {
        pem = pem + "-----END PUBLIC KEY-----";
    }
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pem_contents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    const binaryDerString = atob(pem_contents);
    const binaryDer = str2ab(binaryDerString);
    return crypto.subtle.importKey("spki", binaryDer, {
        name: "ECDSA",
        namedCurve: "P-521",
    }, true, ["verify"]);
}
exports.importEllipticPublicKey = importEllipticPublicKey;
function importEllipticPrivateKey(pem) {
    if (!pem.startsWith("-----BEGIN PRIVATE KEY-----")) {
        pem = "-----BEGIN PRIVATE KEY-----" + pem;
    }
    if (!pem.endsWith("-----END PRIVATE KEY-----")) {
        pem = pem + "-----END PRIVATE KEY-----";
    }
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pem_contents = pem.substring(pemHeader.length, pem.length - pemFooter.length);
    const binaryDerString = atob(pem_contents);
    const binaryDer = str2ab(binaryDerString);
    return crypto.subtle.importKey("pkcs8", binaryDer, {
        name: "ECDSA",
        hash: "SHA-256",
        namedCurve: "P-521"
    }, true, ["sign"]);
}
exports.importEllipticPrivateKey = importEllipticPrivateKey;
function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
function VerifyJWT(jwt_string, public_key) {
    return __awaiter(this, void 0, void 0, function* () {
        if (isNullOrWhiteSpace(jwt_string)) {
            throw "jwt is null.";
        }
        if (isNullOrWhiteSpace(public_key)) {
            throw "public_key is null or whitespace";
        }
        const publicKeyPem = '-----BEGIN PUBLIC KEY-----\n' +
            `${public_key}\n` +
            '-----END PUBLIC KEY-----\n';
        const decoded_data = yield jsonwebtoken_1.default.verify(jwt_string, publicKeyPem);
        return decoded_data;
    });
}
exports.VerifyJWT = VerifyJWT;
function signJWT(data, privateKeyV) {
    return __awaiter(this, void 0, void 0, function* () {
        const options = {
            algorithm: 'ES512',
            compact: true,
            fields: { typ: 'JWT' }
        };
        const privateKeyPem = '-----BEGIN PRIVATE KEY-----\n' +
            `${privateKeyV.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")}\n` +
            '-----END PRIVATE KEY-----\n';
        const privateKey = yield (0, jose_1.importPKCS8)(privateKeyPem, "ES512");
        const jwt = yield new jose_1.SignJWT(data) // ECDSA with P-521 curve
            .setProtectedHeader({ alg: 'ES512' }) // Optional if you want to specify headers
            .sign(privateKey);
        return jwt;
    });
}
exports.signJWT = signJWT;
function JSONorForm(variable) {
    return __awaiter(this, void 0, void 0, function* () {
        if (variable instanceof FormData) {
            return 'FormData';
        }
        // Check if it's JSON
        try {
            JSON.parse(JSON.stringify(variable));
            return 'JSON';
        }
        catch (error) {
        }
        return null;
    });
}
exports.JSONorForm = JSONorForm;
