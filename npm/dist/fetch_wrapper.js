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
const sign_1 = __importDefault(require("./sign"));
function fetch_wrapper(url, properties, deviceid, private_key, react_native_compatability) {
    return __awaiter(this, void 0, void 0, function* () {
        if (!url) {
            throw `url is ${url}`;
        }
        let urlData = null;
        if (react_native_compatability == true) {
            const { URL: React_Url, URLSearchParams: React_URLSearchParams } = require("react-native-url-polyfill");
            urlData = new React_Url(url);
        }
        else {
            urlData = new URL(url);
        }
        const pathname = urlData.pathname;
        const searchParams = urlData.searchParams;
        // Convert the search parameters to an object
        let paramsObj = {};
        for (const [key, value] of searchParams.entries()) {
            paramsObj[key] = value;
        }
        let jsonOrForm = null;
        let signed_auth_object = {};
        if (properties && properties.method && properties.method.toLowerCase() == "post") {
            const jsonOrFormV = yield (0, globals_1.JSONorForm)(properties.body);
            jsonOrForm = jsonOrFormV;
            if (jsonOrForm == "JSON") {
                const body = JSON.parse(properties.body);
                let bodyObject = Object.assign(Object.assign({}, body), { pathname: pathname, authenticator_JWT_Token: deviceid });
                properties.headers = Object.assign(Object.assign({}, properties.headers), { "Content-Type": "application/json" });
                properties.body = JSON.stringify(bodyObject);
            }
            else if (jsonOrForm == "FormData") {
                throw "Cannot do formdata right now.";
                // const hashData = new TextEncoder().encode(Buffer.from(await internal().getFileBinary(await properties.body.get("file"))));
                // const hashBuffer = await crypto.subtle.digest("SHA-256", hashData);
                // const hashArray = Array.from(new Uint8Array(hashBuffer));
                // const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
                // signed_auth_object = JSON.stringify({
                //     hash: hashHex
                // })
            }
            else {
                // I don't think this is needed?
                let bodyObject = {
                    pathname: pathname,
                    authenticator_JWT_Token: deviceid
                };
                properties.headers = Object.assign(Object.assign({}, properties.headers), { "Content-Type": "application/json" });
                properties.body = JSON.stringify(bodyObject);
            }
        }
        let data_to_be_hashed_for_signing = Object.assign({}, paramsObj);
        if (jsonOrForm == "FormData") {
            data_to_be_hashed_for_signing = Object.assign(Object.assign({}, data_to_be_hashed_for_signing), { signed_auth_object: signed_auth_object });
            properties.body.append("signed_auth_object", signed_auth_object);
        }
        else if (properties.body && typeof properties.body == "string") {
            data_to_be_hashed_for_signing = Object.assign(Object.assign({}, data_to_be_hashed_for_signing), JSON.parse(properties.body));
        }
        const token = yield (0, sign_1.default)(data_to_be_hashed_for_signing, new URLSearchParams(paramsObj).toString(), private_key);
        if (properties.method == "POST") {
            properties.body = Object.assign(Object.assign({}, properties.body), { authenticator_JWT_Token: token });
        }
        else {
            paramsObj = Object.assign(Object.assign({}, paramsObj), { authenticator_JWT_Token: token });
        }
        let formDataOutput = new URLSearchParams(paramsObj);
        let outputUrl = `${urlData.origin}${urlData.pathname}`;
        if (formDataOutput.toString() && formDataOutput.toString().length > 0) {
            outputUrl = outputUrl + "?" + formDataOutput.toString();
        }
        return yield fetch(outputUrl, properties);
    });
}
exports.default = fetch_wrapper;
