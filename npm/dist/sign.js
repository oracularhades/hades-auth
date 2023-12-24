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
function sign(body, params, private_key) {
    return __awaiter(this, void 0, void 0, function* () {
        let keys = [];
        let unsorted_data = {};
        let params_object = {};
        if (params) {
            params_object = Object.fromEntries(new URLSearchParams(params));
        }
        unsorted_data = Object.assign(Object.assign({}, params_object), body);
        keys = Object.keys(unsorted_data).sort();
        let data = {};
        yield keys.forEach((key) => {
            data[key] = unsorted_data[key];
        });
        const hash = crypto_1.default.createHash('sha512');
        hash.update(JSON.stringify(data));
        const output_sha512_checksum = hash.digest('hex');
        data = {
            checksum: output_sha512_checksum
        };
        let jwt = yield (0, globals_1.signJWT)(data, private_key);
        return jwt;
    });
}
exports.default = sign;
