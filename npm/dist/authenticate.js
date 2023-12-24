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
const globals_1 = require("./globals");
const crypto_1 = __importDefault(require("crypto"));
function authenticate(body, params, jwt, public_key, pathname, filebuffer) {
    return __awaiter(this, void 0, void 0, function* () {
        // if (filebuffer) {
        //     let obj = req.body;
        //     if (!obj || !obj.signed_auth_object) {
        //         throw "Your request is formdata and missing body.signed_auth_object";
        //     }
        //     let signed_auth_object = null;
        //     try {
        //         signed_auth_object = JSON.parse(req.body.signed_auth_object);
        //     } catch {
        //         throw "signed_auth_object is not an object.";
        //     }
        //     const hashData = new TextEncoder().encode(Buffer.from(filebuffer));
        //     const hashBuffer = await crypto.subtle.digest("SHA-256", hashData);
        //     const hashArray = Array.from(new Uint8Array(hashBuffer));
        //     const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
        //     if (hashHex != signed_auth_object.hash) {
        //         console.log("DOESN'T MATCH", hashHex, signed_auth_object.hash);
        //         throw "Hash in signed_auth_object and hash for provided formdata file does not match. (Your hash should be in hex)";
        //     }
        // }
        let keys = [];
        let unsorted_data = {};
        let params_object = Object.fromEntries(new URLSearchParams(params));
        unsorted_data = Object.assign(Object.assign({}, params_object), body);
        keys = Object.keys(unsorted_data).sort();
        let data = {};
        yield keys.forEach((key) => {
            if (key != "authenticator_metadata" && key != "authenticator_JWT_Token") {
                data[key] = unsorted_data[key];
            }
        });
        // Make sure deviceid and JWT_Token are specified.
        if ((0, globals_1.isNullOrWhiteSpace)(jwt)) {
            throw "JWT is null or whitespace.";
        }
        // Check the pathname inside the signed-object, it needs to match the current pathname, this makes it more annoying for attackers to re-play signed packets. Such as if 2 API endpoints use similar properties, it's locked to the API endpoint is was signed for.
        const data_pathname = data.pathname;
        if ((0, globals_1.isNullOrWhiteSpace)(data_pathname)) {
            throw "signedObject.pathname is null or whitespace.";
        }
        if (data_pathname != pathname) {
            throw `Signed URL is "${data_pathname}" and does not match "${pathname}"`;
        }
        const verify_jwt_status = yield (0, globals_1.VerifyJWT)(jwt, public_key); // an error will throw here if the request is unauthorized.
        let sha512_authed_checksum = '';
        if (typeof verify_jwt_status === 'string') {
            throw "VerifyJWT output was a string for some reason.";
        }
        else {
            const sha512_authed_checksum_v = verify_jwt_status.checksum.toString();
            sha512_authed_checksum = sha512_authed_checksum_v;
        }
        const hash = crypto_1.default.createHash('sha512');
        hash.update(JSON.stringify(data));
        const output_sha512_for_unverified_data = hash.digest('hex');
        if (sha512_authed_checksum != output_sha512_for_unverified_data) {
            // data object does not match checksum in JWT.
            throw "Incoming data does not match checksum in JWT packet.";
        }
        return true;
    });
}
exports.default = authenticate;
