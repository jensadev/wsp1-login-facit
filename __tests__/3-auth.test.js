const app = require('../app');
const request = require('supertest');
const session = require('supertest-session');
const pool = require('../utils/database');
const bcrypt = require('bcrypt');

describe('3. Authentication', () => {
    let testSession = null;
    /** Setup
     * Before all tests, we create the user in the database
     * and create a session for the tests
     */
    beforeAll(async () => {
        testSession = await session(app);
        try {
            const hash = await bcrypt.hash('test', 10);
            await pool
                .promise()
                .query(`INSERT INTO users (name, password) VALUES (?,?)`, [
                    'test',
                    hash,
                ]);
        } catch (error) {
            console.log('Something went wrong with database setup: ');
            console.log(error);
        }
    });

    describe('without authentication', () => {
        describe('GET /profile', () => {
            it('should return a 401 response', async () => {
                expect.assertions(2);
                const response = await request(app).get('/profile');
                expect(response.statusCode).toBe(401);
                expect(response.text).toContain('Access denied');
            });
        });
        describe('POST /logout', () => {
            it('should return a 401 response', async () => {
                expect.assertions(2);
                const response = await request(app).post('/logout');
                expect(response.statusCode).toBe(401);
                expect(response.text).toContain('Access denied');
            });
        });
    });
    describe('with authentication', () => {
        let authenticatedSession;

        /** Setup
         * Before east tests, we login the user
         * and create a session for the tests
         */
        beforeEach(async () => {
            await testSession.post('/login').send({
                username: 'test',
                password: 'test',
            });
            authenticatedSession = testSession;
        });

        describe('GET /profile', () => {
            it('should return a 200 response', async () => {
                expect.assertions(1);
                const response = await authenticatedSession.get('/profile');
                expect(response.statusCode).toBe(200);
            });
            it('should return a html response with a profile page', async () => {
                expect.assertions(1);
                const response = await authenticatedSession.get('/profile');
                expect(response.text).toContain('<h1>Profile</h1>');
            });
            it('should return a html response with a profile page with a username', async () => {
                expect.assertions(1);
                const response = await authenticatedSession.get('/profile');
                expect(response.text).toContain('<p>Username: test</p>');
            });
            it('should return a html response with a profile page with a logout button', async () => {
                expect.assertions(1);
                const response = await authenticatedSession.get('/profile');
                expect(response.text).toContain(
                    '<button type="submit">Logout</button>',
                );
            });
        });
        describe('POST /logout', () => {
            it('should return a 200 response', async () => {
                expect.assertions(2);
                const response = await authenticatedSession.post('/logout');
                expect(response.statusCode).toBe(302);
                expect(response.headers.location).toBe('/');
            });
        });
        afterEach(async () => {
            /* Destroy the session */
            await authenticatedSession.destroy();
        });
    });
    /** Teardown
     * After all tests, we delete the users from the database
     * and close the session
     * We also close the database connection
     */
    afterAll(async () => {
        try {
            await pool.promise().query('DELETE FROM users WHERE name = "asdf"');
            await pool.promise().query('DELETE FROM users WHERE name = "test"');
        } catch (error) {
            console.log('Something went wrong with database cleanup: ');
            console.log(error);
        }
        await pool.end();
        await testSession.destroy();
    });
});
