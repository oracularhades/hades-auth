import { signJWT } from "../globals.js";
export default async function static_auth_sign(additional_data, private_key) {
    let jwt_data = {
        additional_data: additional_data,
        created: new Date().getTime(),
        exp: new Date().getTime() + 31536000000
    };
    let jwt = await signJWT(jwt_data, private_key);
    return jwt;
}
