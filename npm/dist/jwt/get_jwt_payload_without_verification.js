import jwt from 'jsonwebtoken';
export default function get_jwt_payload_without_verification(jwt_string) {
    try {
        const decodedPayload = jwt.decode(jwt_string, { complete: true });
        if (decodedPayload) {
            return decodedPayload.payload;
        }
        else {
            throw "Invalid JWT";
        }
    }
    catch (error) {
        throw error;
    }
}
