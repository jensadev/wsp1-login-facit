const app = require('../app');
const supertest = require('supertest');
const bcrypt = require('bcrypt');

describe('1. Setup', () => {
    describe('GET / ', () => {
        it('should return a 200 response', async () => {
            expect.assertions(1);
            const response = await supertest(app).get('/');
            expect(response.statusCode).toBe(200);
        });
        it('should return a html response', async () => {
            expect.assertions(1);
            const response = await supertest(app).get('/');
            expect(response.headers['content-type']).toBe(
                'text/html; charset=utf-8',
            );
        });
        it('should return a html response with title', async () => {
            expect.assertions(1);
            const response = await supertest(app).get('/');
            expect(response.text).toContain('<h1>Login ALC</h1>');
        });
    });

    describe('GET /crypt/:pwd', () => {
        it('should return a 200 response', async () => {
            expect.assertions(1);
            const response = await supertest(app).get('/crypt/123');
            expect(response.statusCode).toBe(200);
        });
        it('should return a json response', async () => {
            expect.assertions(1);
            const response = await supertest(app).get('/crypt/123');
            expect(response.headers['content-type']).toBe(
                'application/json; charset=utf-8',
            );
        });
        it('should return a json response with encrypted password', async () => {
            expect.assertions(1);
            const pwd = 'Supersecret+password123';
            const response = await supertest(app).get(`/crypt/${pwd}`);
            expect(response.body.hash).toBeDefined();
        });
    });
});
