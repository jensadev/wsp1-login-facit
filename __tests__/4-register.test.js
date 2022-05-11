const app = require('../app');
const request = require('supertest');
const pool = require('../utils/database');

describe('4. Registration', () => {
    beforeAll(async () => {
        await pool
            .promise()
            .query('DELETE FROM users WHERE name = "asdf"');
    });
    describe('GET /register', () => {
        it('should return a 200 response', async () => {
            expect.assertions(1);
            const response = await request(app).get('/register');
            expect(response.statusCode).toBe(200);
        });
        it('should return a html response with form', async () => {
            expect.assertions(1);
            const response = await request(app).get('/register');
            expect(response.text).toContain(
                '<form action="/register" method="POST">',
            );
        });
        it('should return a html response with a username field', async () => {
            expect.assertions(1);
            const response = await request(app).get('/register');
            expect(response.text).toContain(
                '<input type="text" name="username"',
            );
        });
        it('should return a html response with a password field', async () => {
            expect.assertions(1);
            const response = await request(app).get('/register');
            expect(response.text).toContain(
                '<input type="password" name="password"',
            );
        });
        it('should return a html response with a password confirmation field', async () => {
            expect.assertions(1);
            const response = await request(app).get('/register');
            expect(response.text).toContain(
                '<input type="password" name="passwordConfirmation"',
            );
        });
        it('should return a html response with a submit button', async () => {
            expect.assertions(1);
            const response = await request(app).get('/register');
            expect(response.text).toContain(
                '<button type="submit">Register</button>',
            );
        });
    });
    describe('POST /register', () => {
        it('should give an error with empty credential fields', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/register')
                .send({ username: '', password: '', passwordConfirmation: '' });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Username is Required');
        });
        it('should give an error with empty username field', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/register')
                .send({
                    username: '',
                    password: 'asdf',
                    passwordConfirmation: 'asdf',
                });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Username is Required');
        });
        it('should give an error with empty password field', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/register')
                .send({
                    username: 'test',
                    password: '',
                    passwordConfirmation: 'asdf',
                });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Password is Required');
        });
        it('should give an error when passwords do not match', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/register')
                .send({
                    username: 'test',
                    password: 'asdf',
                    passwordConfirmation: '',
                });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Passwords do not match');
        });
        it('should give an error when username is already taken', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/register')
                .send({
                    username: 'test',
                    password: 'asdf',
                    passwordConfirmation: 'asdf',
                });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Username is already taken');
        });
        it('should register the user with correct credentials and redirect to /login', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/register')
                .send({
                    username: 'asdf',
                    password: 'asdf',
                    passwordConfirmation: 'asdf',
                });
            expect(response.statusCode).toBe(302);
            expect(response.headers.location).toBe('/login');
        });
        it('it should login the registered user', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/login')
                .send({ username: 'asdf', password: 'asdf' });
            expect(response.statusCode).toBe(302);
            expect(response.headers.location).toBe('/profile');
        });
    });
    afterAll(async () => {
        await pool.end();
    });
});
