const app = require('../app');
const request = require('supertest');
const session = require('supertest-session');
const pool = require('../utils/database');
const bcrypt = require('bcrypt');

const usersTable = process.env.DATABASE_USERSTABLE;
const [user1, user2, user3] = require('../__mocks__/users');

describe('5. Delete', () => {
    let testSession = null;
    /** Setup
     * Before all tests, we create the user in the database
     * and create a session for the tests
     */
    beforeAll(async () => {
        testSession = await session(app);
        try {
            const hash = await bcrypt.hash(user3.password, 10);
            await pool
                .promise()
                .query(
                    `INSERT INTO ${usersTable} (name, password) VALUES (?,?)`,
                    [user3.name, hash],
                );
        } catch (error) {
            console.log('Something went wrong with database setup: ');
            console.log(error);
        }
    });

    describe('without authentication', () => {
        describe('POST /users/delete', () => {
            it('should return a 401 response', async () => {
                expect.assertions(2);
                const response = await request(app).post('/users/delete');
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
                username: user3.name,
                password: user3.password,
            });
            authenticatedSession = testSession;
        });
        describe('POST /users/delete', () => {
            it('should return a 302 response', async () => {
                expect.assertions(2);
                const response = await authenticatedSession.post(
                    '/users/delete',
                );
                expect(response.statusCode).toBe(302);
                expect(response.headers.location).toBe('/');
            });

            it('should delete the user from the database', async () => {
                expect.assertions(1);
                await authenticatedSession.post('/users/delete');
                const [rows] = await pool
                    .promise()
                    .query(`SELECT * FROM ${usersTable} WHERE name = ?`, [
                        user3.name,
                    ]);
                expect(rows.length).toBe(0);
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
            await pool
                .promise()
                .query(`DELETE FROM ${usersTable} WHERE name = ?`, [
                    user3.name,
                ]);
        } catch (error) {
            console.log('Something went wrong with database cleanup: ');
            console.log(error);
        }
        await pool.end();
        await testSession.destroy();
    });
});
