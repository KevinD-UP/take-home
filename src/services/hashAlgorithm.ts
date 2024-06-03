import crypto from "crypto";
import {Payload} from "./signatureService";

/**
 * Interface representing a hash algorithm.
 */
export interface HashAlgorithm {
    /**
     * hash the given data using the algorithm.
     * @param {Payload} data - The data to hash.
     * @returns {string} - The data after hash.
     */
    hash: (payload: Payload) => string;
}

const secret = "mysecret"

export class HashAlgorithmSha256 implements HashAlgorithm {
    hash(payload: Payload): string {
        const hmac = crypto.createHmac('sha256', secret);
        hmac.update(JSON.stringify(payload));
        return hmac.digest('hex');
    }
}
