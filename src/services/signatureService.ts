import {HashAlgorithm} from "./hashAlgorithm";

type Payload = any;

export class SignatureService {

    constructor(private hashAlgorithm: HashAlgorithm) {}

    /**
     * Generate HMAC signature for the given payload and secret.
     * @param {Payload} payload - The payload to generate the signature for.
     * @returns {string} - The HMAC signature.
     * @throws {Error} - If the payload or secret is null or undefined.
     */
    generateHmacSignature = (payload: Payload): string => {
        if (!payload) {
            throw new Error('Payload cannot be null or undefined');
        }
        return this.hashAlgorithm.hash(payload)
    };

    /**
     * Verify if the given signature matches the expected HMAC signature for the payload and secret.
     * @param {Payload} payload - The payload to verify the signature for.
     * @param {string} signature - The signature to verify.
     * @returns {boolean} - True if the signature is valid, false otherwise.
     * @throws {Error} - If the signature or secret is null, undefined, or not a non-empty string.
     */
    verifyHmacSignature = (payload: Payload, signature: string): boolean => {
        if (!signature) {
            throw new Error('Signature must be a non-empty string');
        }
        const expectedSignature = this.generateHmacSignature(payload);
        return expectedSignature === signature;
    };
}

