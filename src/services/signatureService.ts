import {HashAlgorithm} from "./hashAlgorithm";

export type Payload = Record<string, any>;
export type verifyHmacSignatureArg = { signature: string, data: Payload, }

export class SignatureService {

    constructor(private hashAlgorithm: HashAlgorithm) {}

    /**
     * Sets a new hash algorithm.
     * @param algorithm - The new encryption algorithm to use.
     */
    setAlgorithm(algorithm: HashAlgorithm) {
        this.hashAlgorithm = algorithm;
    }

    /**
     * Generate HMAC signature for the given payload and secret.
     * Assumes `payload` has been validated at the route level.
     * @param {Payload} payload - The payload to generate the signature for.
     * @returns {string} - The HMAC signature.
     */
    generateHmacSignature = (payload: Payload): string => {
        return this.hashAlgorithm.hash(payload)
    };

    /**
     * Verify if the given signature matches the expected HMAC signature for the payload and secret.
     * Assumes `payload` has been validated at the route level.
     * @param {Payload} payload - The payload to verify the signature for.
     * @returns {boolean} - True if the signature is valid, false otherwise.
     */
    verifyHmacSignature = (payload: verifyHmacSignatureArg): boolean => {
        const expectedSignature = this.generateHmacSignature(payload.data);
        return expectedSignature === payload.signature;
    };
}

