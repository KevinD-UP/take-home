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
