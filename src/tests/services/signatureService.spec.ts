import {expect} from 'chai';
import {Payload, SignatureService} from '../../services/signatureService';
import {HashAlgorithm, HashAlgorithmSha256} from "../../services/hashAlgorithm";

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
            expect(() => signatureService.generateHmacSignature(null as any)).to.throw('Payload cannot be null or undefined');
            expect(() => signatureService.generateHmacSignature(undefined as any)).to.throw('Payload cannot be null or undefined');
        });

    });

    describe('verifyHmacSignature', () => {
        it('should return true for a valid signature', () => {
            const payload = {foo: 'bar'};
            const signature = signatureService.generateHmacSignature(payload);

            const isValid = signatureService.verifyHmacSignature({signature, data: payload});

            expect(isValid).to.be.true;
        });

        it('should return false for an invalid signature', () => {
            const payload = {foo: 'bar'};
            const invalidSignature = 'invalidsignature';

            const isValid = signatureService.verifyHmacSignature({signature: invalidSignature, data: payload});

            expect(isValid).to.be.false;
        });

        it('should throw an error if signature is null, undefined, or not a string', () => {
            const payload = {foo: 'bar'};
            expect(() => signatureService.verifyHmacSignature({signature: null as any, data: payload})).to.throw('Signature must be a non-empty string');
            expect(() => signatureService.verifyHmacSignature({signature: undefined as any, data: payload})).to.throw('Signature must be a non-empty string');
        });
    });

    describe('setAlgorithm', () => {
        class MockAlgorithm implements HashAlgorithm {
            hash(payload: Payload): string {
                return "";
            }
        }

        it('should set a new encryption algorithm', () => {
            const mockAlgorithm = new MockAlgorithm();

            signatureService.setAlgorithm(mockAlgorithm);

            const obj = {foo: 'bar'};
            const res = signatureService.generateHmacSignature(obj);

            expect(res).to.equal("");
        });
    })
});
