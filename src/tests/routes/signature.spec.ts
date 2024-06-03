import request from "supertest";
import app from "../../app";
import {expect} from "chai";
import crypto from "crypto";

describe('Signature API', () => {
    describe('Sign API', () => {
        it('should generate a HMAC signature for the payload', async () => {
            const payload = {foo: "bar"};
            const secret = "mysecret";

            const res = await request(app).post('/sign').send(payload);
            expect(res.status).to.equal(200);
            expect(res.body).to.have.property('signature');

            const hmac = crypto.createHmac('sha256', secret);
            hmac.update(JSON.stringify(payload));
            const expectedSignature = hmac.digest('hex');

            expect(res.body.signature).to.equal(expectedSignature);
        });

        it('should return 400 Bad Request when payload is missing', async () => {
            const res = await request(app).post('/sign');

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });

        it('should return status 400 if request body is empty for /sign endpoint', async () => {
            const payload = {};

            const res = await request(app).post('/sign').send(payload);

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });


        it('should return status 400 if request is not an object for /sign endpoint', async () => {
            const payload = 'not an object';

            const res = await request(app).post('/sign').send(payload);

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });
    });

    describe('Verify API', () => {
        it('should return 204 if the signature is valid', async () => {
            const payload = {foo: "bar"};
            const secret = 'mysecret';
            const hmac = crypto.createHmac('sha256', secret);
            hmac.update(JSON.stringify(payload));
            const signature = hmac.digest('hex');

            const res = await request(app).post('/verify').send({
                signature,
                data: payload
            });

            expect(res.status).to.equal(204);
        });

        it('should return 400 if the signature is invalid', async () => {
            const payload = {foo: "bar"};
            const invalidSignature = 'invalidsignature';

            const res = await request(app).post('/verify').send({
                signature: invalidSignature,
                data: payload
            });

            expect(res.status).to.equal(400);
        });

        it('should return status 400 if request body has no payload for /verify endpoint', async () => {
            const res = await request(app).post('/verify');

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });

        it('should return status 400 if request body is empty for /verify endpoint', async () => {
            const payload = {};

            const res = await request(app).post('/verify').send(payload);

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });

        it('should return status 400 if signature is not a string for /verify endpoint', async () => {
            const payload = {
                signature: 123, // Invalid signature type
                data: {}       // Dummy data
            };

            const res = await request(app).post('/verify').send(payload);

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });

        it('should return status 400 if data is not an object for /verify endpoint', async () => {
            const payload = {
                signature: 'validSignature', // Valid signature
                data: 'not an object'        // Invalid data type
            };

            const res = await request(app).post('/verify').send(payload);

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });

        it('should return status 400 if there is no signature for /verify endpoint', async () => {
            const payload = {
                data: { foo: "bar"}
            };

            const res = await request(app).post('/verify').send(payload);

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });

        it('should return status 400 if there is no data for /verify endpoint', async () => {
            const payload = {
                signature: 'validSignature',
            };

            const res = await request(app).post('/verify').send(payload);

            expect(res.status).to.equal(400);
            expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
        });
    });
})