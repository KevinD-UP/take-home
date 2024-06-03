import {expect} from 'chai';
import sinon from 'sinon';
import {Payload, SignatureService} from '../../services/signatureService';
import {HashAlgorithm, HashAlgorithmSha256} from "../../services/hashAlgorithm";

describe('HMAC Service', () => {
    let signatureServiceUsingSha256: SignatureService;
    let signatureServiceUsingStub: SignatureService;
    let stubAlgorithm: { hash: sinon.SinonStub };

    before(() => {
        signatureServiceUsingSha256 = new SignatureService(new HashAlgorithmSha256());

        stubAlgorithm = {
            hash: sinon.stub()
        };

        signatureServiceUsingStub = new SignatureService(stubAlgorithm as any);
    });

    afterEach(() => {
        sinon.resetHistory()
    });

    describe('generateHmacSignature', () => {
        it('should generate a valid HMAC signature using SHA256', () => {
            const payload = {foo: 'bar'};
            const signature = signatureServiceUsingSha256.generateHmacSignature(payload);

            expect(signature).to.be.a('string');
            expect(signature).to.have.lengthOf(64); // HMAC-SHA256 signature length
        });

        it('should generate a valid HMAC signature using stubs', () => {
            const payload = {foo: 'bar'};
            const stubSignature = 'stubbed_signature';
            stubAlgorithm.hash.returns(stubSignature);

            const signature = signatureServiceUsingStub.generateHmacSignature(payload);

            expect(signature).to.equal(stubSignature);
            expect(stubAlgorithm.hash.calledOnceWith(payload)).to.be.true;
        });
    });

    describe('verifyHmacSignature', () => {
        it('should return true for a valid signature using SHA256', () => {
            const payload = {foo: 'bar'};
            const signature = signatureServiceUsingSha256.generateHmacSignature(payload);

            const isValid = signatureServiceUsingSha256.verifyHmacSignature({signature, data: payload});

            expect(isValid).to.be.true;
        });

        it('should return true for a valid signature using stubs', () => {
            const payload = {foo: 'bar'};
            const stubSignature = 'stubbed_signature';
            stubAlgorithm.hash.onFirstCall().returns(stubSignature);
            stubAlgorithm.hash.onSecondCall().returns(stubSignature);

            const signature = signatureServiceUsingStub.generateHmacSignature(payload);

            const isValid = signatureServiceUsingStub.verifyHmacSignature({signature, data: payload});

            expect(isValid).to.be.true;
            expect(stubAlgorithm.hash.calledTwice).to.be.true; // called in generateHmacSignature and verifyHmacSignature
            expect(stubAlgorithm.hash.alwaysCalledWith(payload)).to.be.true;
        });

        it('should return false for an invalid signature using SHA256', () => {
            const payload = {foo: 'bar'};
            const invalidSignature = 'invalidsignature';

            const isValid = signatureServiceUsingSha256.verifyHmacSignature({signature: invalidSignature, data: payload});

            expect(isValid).to.be.false;
        });

        it('should return false for an invalid signature using stubs', () => {
            const payload = {foo: 'bar'};
            const stubSignature = 'stubbed_signature';
            stubAlgorithm.hash.returns(stubSignature);

            const invalidSignature = 'invalidsignature';

            const isValid = signatureServiceUsingStub.verifyHmacSignature({signature: invalidSignature, data: payload});

            expect(isValid).to.be.false;
            expect(stubAlgorithm.hash.calledOnceWith(payload)).to.be.true;
        });
    });

    describe('setAlgorithm', () => {
        class MockAlgorithm implements HashAlgorithm {
            hash(payload: Payload): string {
                return `mock-hash(${JSON.stringify(payload)})`;
            }
        }

        it('should set a new encryption algorithm using a mock', () => {
            const mockAlgorithm = new MockAlgorithm();

            signatureServiceUsingSha256.setAlgorithm(mockAlgorithm);

            const obj = {foo: 'bar'};
            const res = signatureServiceUsingSha256.generateHmacSignature(obj);

            expect(res).to.equal(`mock-hash(${JSON.stringify(obj)})`);
        });

        it('should set a new encryption algorithm using stubs', () => {
            const stubHash = sinon.stub().returns('stub-hash');

            const mockAlgorithm = {
                hash: stubHash
            };

            signatureServiceUsingSha256.setAlgorithm(mockAlgorithm as any);

            const obj = {foo: 'bar'};
            const res = signatureServiceUsingSha256.generateHmacSignature(obj);

            expect(res).to.equal('stub-hash');
            expect(stubHash.calledOnceWith(obj)).to.be.true;
        });
    });
});
