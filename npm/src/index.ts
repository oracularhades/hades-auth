import authenticate from "./authenticate";
import onboard_new_device from "./onboard_new_device";
import sign from "./sign";

function Authenticator() {
    return {
        sign: sign,
        authenticate: authenticate,
        onboard_new_device: onboard_new_device
    };
}

export default Authenticator;