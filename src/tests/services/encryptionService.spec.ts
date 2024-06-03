import {expect} from 'chai';
import sinon from 'sinon';
import {EncryptionService} from '../../services/encryptionService';
import {Base64Algorithm} from "../../services/encryptionAlgorithm";

describe('EncryptionService', () => {
    let encryptionServiceUsingBase64: EncryptionService;
    let encryptionServiceUsingStub: EncryptionService;
    let stubAlgorithm: { encrypt: sinon.SinonStub, decrypt: sinon.SinonStub };

    before(() => {
        encryptionServiceUsingBase64 = new EncryptionService(new Base64Algorithm());

        stubAlgorithm = {
            encrypt: sinon.stub(),
            decrypt: sinon.stub()
        };

        encryptionServiceUsingStub = new EncryptionService(stubAlgorithm as any);
    });

    afterEach(() => {
        sinon.restore();
    });

    describe('encryptObject', () => {
        it('should encrypt every value in the object using Base64', () => {
            const obj = {
                foo: 'bar',
                baz: 123,
                nested: {nestedProp: 'nestedValue'}
            };

            const encryptedObj = encryptionServiceUsingBase64.encryptObject(obj);

            Object.keys(obj).forEach(key => {
                expect(encryptedObj).to.have.property(key);
                expect(encryptedObj[key]).to.be.a('string');
            });
        });

        it('should return an empty object if the input object is empty using Base64', () => {
            const obj = {};
            const encryptedObj = encryptionServiceUsingBase64.encryptObject(obj);

            expect(Object.keys(encryptedObj)).to.have.lengthOf(0);
        });

        it('should encrypt every value in the object using stubs', () => {
            const obj = {
                foo: 'bar',
                baz: 123,
                nested: {nestedProp: 'nestedValue'}
            };

            stubAlgorithm.encrypt.callsFake((data) => `stub-encrypt(${data})`);

            const encryptedObj = encryptionServiceUsingStub.encryptObject(obj);

            Object.keys(obj).forEach(key => {
                expect(encryptedObj).to.have.property(key);
                expect(encryptedObj[key]).to.match(/^stub-encrypt\(.+\)$/);
            });

            expect(stubAlgorithm.encrypt.callCount).to.equal(Object.keys(obj).length);
            Object.values(obj).forEach(value => {
                expect(stubAlgorithm.encrypt.calledWith(JSON.stringify(value))).to.be.true;
            });
        });

        it('should return an empty object if the input object is empty using stubs', () => {
            const obj = {};
            const encryptedObj = encryptionServiceUsingStub.encryptObject(obj);

            expect(Object.keys(encryptedObj)).to.have.lengthOf(0);

            expect(stubAlgorithm.encrypt.called).to.be.true;
        });
    });

    describe('decryptObject', () => {
        it('should decrypt every value in the object using Base64', () => {
            const obj = {
                foo: 'YmFy', // 'bar' encrypted
                baz: 'MTIz', // '123' encrypted
                nested: 'eyJuZXN0ZWRQcm9wIjoibmVzdGVkVmFsdWUifQ==' // '{"nestedProp":"nestedValue"}' encrypted
            };

            const decryptedObj = encryptionServiceUsingBase64.decryptObject(obj);

            expect(decryptedObj.foo).to.equal('bar');
            expect(decryptedObj.baz).to.equal(123);
            expect(decryptedObj.nested).to.deep.equal({nestedProp: 'nestedValue'});
        });

        it('should return an empty object if the input object is empty using Base64', () => {
            const obj = {};
            const decryptedObj = encryptionServiceUsingBase64.decryptObject(obj);

            expect(Object.keys(decryptedObj)).to.have.lengthOf(0);
        });

        it('should decrypt every value in the object using stubs', () => {
            const obj = {
                foo: 'stub-encrypt("bar")',
                baz: 'stub-encrypt("123")',
                nested: 'stub-encrypt({"nestedProp":"nestedValue"})'
            };

            stubAlgorithm.decrypt.callsFake((data) => data.replace('stub-encrypt(', '').replace(')', ''));

            const decryptedObj = encryptionServiceUsingStub.decryptObject(obj);

            expect(decryptedObj.foo).to.equal('bar');
            expect(decryptedObj.baz).to.equal('123');
            expect(decryptedObj.nested).to.deep.equal({"nestedProp":"nestedValue"});

            expect(stubAlgorithm.decrypt.callCount).to.equal(Object.keys(obj).length);
            Object.values(obj).forEach(value => {
                expect(stubAlgorithm.decrypt.calledWith(value)).to.be.true;
            });
        });

        it('should return an empty object if the input object is empty using stubs', () => {
            const obj = {};
            const decryptedObj = encryptionServiceUsingStub.decryptObject(obj);

            expect(Object.keys(decryptedObj)).to.have.lengthOf(0);

            expect(stubAlgorithm.decrypt.called).to.be.true;
        });
    });

    describe('setAlgorithm', () => {
        it('should set a new encryption algorithm and use it for encryption and decryption', () => {
            const mockAlgorithm = {
                encrypt: sinon.stub().callsFake((data: string) => `mock-encrypt(${data})`),
                decrypt: sinon.stub().callsFake((data: string) => data.replace('mock-encrypt(', '').replace(')', ''))
            };

            encryptionServiceUsingBase64.setAlgorithm(mockAlgorithm as any);

            const obj = {foo: 'bar'};
            const encryptedObj = encryptionServiceUsingBase64.encryptObject(obj);
            const decryptedObj = encryptionServiceUsingBase64.decryptObject(encryptedObj);

            expect(encryptedObj.foo).to.equal('mock-encrypt("bar")');
            expect(decryptedObj).to.be.deep.equal({foo: 'bar'});

            expect(mockAlgorithm.encrypt.calledOnceWith(JSON.stringify(obj.foo))).to.be.true;
            expect(mockAlgorithm.decrypt.calledOnceWith(encryptedObj.foo)).to.be.true;
        });
    });
});
