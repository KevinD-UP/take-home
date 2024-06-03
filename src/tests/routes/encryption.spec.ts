import {expect} from 'chai';
import request from 'supertest';
import app from '../../app';

describe('Encryption API', () => {
    it('should encrypt every value in the object', async () => {
        const payload = {
            foo: "foobar",
            bar: {
                isBar: true
            }
        };

        const res = await request(app).post('/encrypt').send(payload);

        expect(res.status).to.equal(200);
        expect(res.body).to.have.property('foo');
        expect(res.body.foo).to.be.a('string');
        expect(res.body).to.have.property('bar');
        expect(res.body.bar).to.be.a('string');
    });

    it('should return 400 Bad Request when payload is missing', async () => {
        const res = await request(app).post('/encrypt');

        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
    });

    it('should return status 400 if request body is empty for /encrypt endpoint', async () => {
        const payload = {};

        const res = await request(app).post('/encrypt').send(payload);

        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
    });

    it('should return 400 Bad Request when payload is not an object', async () => {
        const payload = 'not an object';

        const res = await request(app).post('/encrypt').send(payload);

        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
    });

    it('should decrypt every encrypted value in the object', async () => {
        const encryptedPayload = {
            foo: Buffer.from("foobar").toString('base64'),
            bar: Buffer.from(JSON.stringify({isBar: true})).toString('base64')
        };

        const res = await request(app).post('/decrypt').send(encryptedPayload);

        expect(res.status).to.equal(200);
        expect(res.body).to.have.property('foo', 'foobar');
        expect(res.body).to.have.property('bar');
        expect(res.body.bar).to.be.deep.equal({isBar: true});
    });

    it('should return 400 Bad Request when payload is missing', async () => {
        const res = await request(app).post('/decrypt');

        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
    });

    it('should return status 400 if request body is empty', async () => {
        const payload = {};

        const res = await request(app).post('/decrypt').send(payload);

        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
    });

    it('should return status 400 if request body is not an object', async () => {
        const payload = 'not an object';

        const res = await request(app).post('/decrypt').send(payload);

        expect(res.status).to.equal(400);
        expect(res.body).to.have.property('errors').that.is.an('array').and.not.empty;
    });
});