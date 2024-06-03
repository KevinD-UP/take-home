import {expect} from 'chai';
import {SignatureService} from '../../services/signatureService';
import {HashAlgorithmSha256} from "../../services/hashAlgorithm";

describe('HMAC Service', () => {
    let signatureService: SignatureService;

    before(() => {
        signatureService = new SignatureService(new HashAlgorithmSha256());
    });

    describe('generateHmacSignature', () => {
        it('should generate a valid HMAC signature', () => {
            const payload = {foo: 'bar'};
            const signature = signatureService.generateHmacSignature(payload);

            expect(signature).to.be.a('string');
            expect(signature).to.have.lengthOf(64); // HMAC-SHA256 signature length
        });

        it('should throw an error if payload is null or undefined', () => {
            expect(() => signatureService.generateHmacSignature(null)).to.throw('Payload cannot be null or undefined');
            expect(() => signatureService.generateHmacSignature(undefined)).to.throw('Payload cannot be null or undefined');
        });

    });

    describe('verifyHmacSignature', () => {
        it('should return true for a valid signature', () => {
            const payload = {foo: 'bar'};
            const signature = signatureService.generateHmacSignature(payload);

            const isValid = signatureService.verifyHmacSignature(payload, signature);

            expect(isValid).to.be.true;
        });

        it('should return false for an invalid signature', () => {
            const payload = {foo: 'bar'};
            const invalidSignature = 'invalidsignature';

            const isValid = signatureService.verifyHmacSignature(payload, invalidSignature);

            expect(isValid).to.be.false;
        });

        it('should throw an error if signature is null, undefined, or not a string', () => {
            const payload = {foo: 'bar'};
            expect(() => signatureService.verifyHmacSignature(payload, null as any)).to.throw('Signature must be a non-empty string');
            expect(() => signatureService.verifyHmacSignature(payload, undefined as any)).to.throw('Signature must be a non-empty string');
        });
    });
});
