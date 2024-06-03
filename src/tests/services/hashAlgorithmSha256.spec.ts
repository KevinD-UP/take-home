import { expect } from 'chai';
import { HashAlgorithmSha256 } from '../../services/hashAlgorithm';

describe('HashAlgorithmSha256', () => {
    let hashAlgorithm: HashAlgorithmSha256;

    beforeEach(() => {
        hashAlgorithm = new HashAlgorithmSha256();
    });

    it('should hash the given data using SHA-256 algorithm', () => {
        const payload = {foo: 'example_payload'};
        const secret = 'mysecret';

        // Call the hash method
        const hash = hashAlgorithm.hash(payload);

        // Perform the hashing manually using crypto module
        const crypto = require('crypto');
        const hmac = crypto.createHmac('sha256', secret);
        hmac.update(JSON.stringify(payload));
        const manualHash = hmac.digest('hex');

        // Expectations
        expect(hash).to.equal(manualHash);
    });
});
