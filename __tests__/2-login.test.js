const app = require('../app');
const request = require('supertest');
const pool = require('../utils/database');
const { response } = require('../app');
const bcrypt = require('bcrypt');

const usersTable = process.env.DATABASE_USERSTABLE;
const [user1, user2] = require('../__mocks__/users');

describe('2. Login', () => {
    /** Setup
     * Before all tests, we create the user in the database
     */
    beforeAll(async () => {
        try {
            const hash = await bcrypt.hash(user1.password, 10);
            await pool
                .promise()
                .query(
                    `INSERT INTO ${usersTable} (name, password) VALUES (?,?)`,
                    [user1.name, hash],
                );
        } catch (error) {
            console.log('Something went wrong with database setup: ');
            console.log(error);
        }
    });

    describe('GET /login', () => {
        it('should return a 200 response', async () => {
            expect.assertions(1);
            const response = await request(app).get('/login');
            expect(response.statusCode).toBe(200);
        });
        it('should return a html response with a login form', async () => {
            expect.assertions(1);
            const response = await request(app).get('/login');
            expect(response.text).toContain(
                '<form action="/login" method="POST"',
            );
        });
        it('should return a html response with a username field', async () => {
            expect.assertions(1);
            const response = await request(app).get('/login');
            expect(response.text).toContain(
                '<input type="text" name="username"',
            );
        });
        it('should return a html response with a password field', async () => {
            expect.assertions(1);
            const response = await request(app).get('/login');
            expect(response.text).toContain(
                '<input type="password" name="password"',
            );
        });
        it('should return a html response with a submit button', async () => {
            expect.assertions(1);
            const response = await request(app).get('/login');
            expect(response.text).toContain(
                '<button type="submit">Login</button>',
            );
        });
    });
    describe('POST /login', () => {
        it('should give an error with empty credential fields', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/login')
                .send({ username: '', password: '' });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Username is Required');
        });
        it('should give an error with empty username field', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/login')
                .send({ username: '', password: 'asdf' });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Username is Required');
        });
        it('should give an error with empty password field', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/login')
                .send({ username: user1.name, password: '' });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Password is Required');
        });
        it('should login an user with correct credentials', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/login')
                .send({ username: user1.name, password: user1.password });
            expect(response.statusCode).toBe(302);
            expect(response.header.location).toBe('/profile');
        });
        it('should not login an user with incorrect credentials', async () => {
            expect.assertions(2);
            const response = await request(app)
                .post('/login')
                .send({ username: user1.name, password: 'wrong' });
            expect(response.statusCode).toBe(200);
            expect(response.text).toContain('Invalid username or password');
        });
    });
    /** Teardown
     * After all tests, we delete the users from the database
     * We also close the database connection
     */
    afterAll(async () => {
        try {
            await pool
                .promise()
                .query(`DELETE FROM ${usersTable} WHERE name = ?`, [
                    user1.name,
                ]);
            await pool
                .promise()
                .query(`DELETE FROM ${usersTable} WHERE name = ?`, [
                    user2.name,
                ]);
        } catch (error) {
            console.log('Something went wrong with database cleanup: ');
            console.log(error);
        }
        await pool.end();
    });
});
