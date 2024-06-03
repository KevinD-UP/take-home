import { expect } from 'chai';
import { Base64Algorithm } from '../../services/encryptionAlgorithm';

describe('Base64Algorithm', () => {
    let base64Algorithm: Base64Algorithm;

    before(() => {
        base64Algorithm = new Base64Algorithm();
    });

    describe('encrypt', () => {
        it('should encrypt a string to Base64', () => {
            const data = 'Hello, World!';
            const encrypted = base64Algorithm.encrypt(data);
            expect(encrypted).to.equal(Buffer.from(data).toString('base64'));
        });

        it('should handle empty strings', () => {
            const data = '';
            const encrypted = base64Algorithm.encrypt(data);
            expect(encrypted).to.equal(Buffer.from(data).toString('base64'));
        });

        it('should handle special characters', () => {
            const data = 'Spécial Ch@racter$';
            const encrypted = base64Algorithm.encrypt(data);
            expect(encrypted).to.equal(Buffer.from(data).toString('base64'));
        });
    });

    describe('decrypt', () => {
        it('should decrypt a Base64 string', () => {
            const data = 'Hello, World!';
            const encrypted = Buffer.from(data).toString('base64');
            const decrypted = base64Algorithm.decrypt(encrypted);
            expect(decrypted).to.equal(data);
        });

        it('should handle empty strings', () => {
            const data = '';
            const encrypted = Buffer.from(data).toString('base64');
            const decrypted = base64Algorithm.decrypt(encrypted);
            expect(decrypted).to.equal(data);
        });

        it('should handle special characters', () => {
            const data = 'Spécial Ch@racter$';
            const encrypted = Buffer.from(data).toString('base64');
            const decrypted = base64Algorithm.decrypt(encrypted);
            expect(decrypted).to.equal(data);
        });
    });

    describe('encrypt and decrypt', () => {
        it('should correctly encrypt and decrypt data', () => {
            const data = 'Test data for encryption and decryption';
            const encrypted = base64Algorithm.encrypt(data);
            const decrypted = base64Algorithm.decrypt(encrypted);
            expect(decrypted).to.equal(data);
        });
    });
});
