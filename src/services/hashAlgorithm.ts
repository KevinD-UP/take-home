import crypto from "crypto";

/**
 * Interface representing a hash algorithm.
 */
export interface HashAlgorithm {
    /**
     * hash the given data using the algorithm.
     * @param {string} data - The data to hash.
     * @returns {string} - The data after hash.
     */
    hash: (payload: string) => string;
}

const secret = "mysecret"

export class HashAlgorithmSha256 implements HashAlgorithm {
    hash(payload: string): string {
        const hmac = crypto.createHmac('sha256', secret);
        hmac.update(JSON.stringify(payload));
        return hmac.digest('hex');
    }
}
