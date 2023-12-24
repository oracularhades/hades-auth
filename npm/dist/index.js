"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const authenticate_1 = __importDefault(require("./authenticate"));
const onboard_new_device_1 = __importDefault(require("./onboard_new_device"));
const sign_1 = __importDefault(require("./sign"));
function Authenticator() {
    return {
        sign: sign_1.default,
        authenticate: authenticate_1.default,
        onboard_new_device: onboard_new_device_1.default
    };
}
exports.default = Authenticator;
