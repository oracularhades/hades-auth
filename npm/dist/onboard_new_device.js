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
Object.defineProperty(exports, "__esModule", { value: true });
const globals_1 = require("./globals");
function onboard_new_device(public_key) {
    return __awaiter(this, void 0, void 0, function* () {
        if ((0, globals_1.isNullOrWhiteSpace)(public_key)) {
            throw `public_key is null or whitespace.`;
        }
        const deviceid = yield (0, globals_1.generateRandomID)();
        const publickeyimport = yield (0, globals_1.importEllipticPublicKey)(`-----BEGIN PUBLIC KEY-----
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
    });
}
exports.default = onboard_new_device;
