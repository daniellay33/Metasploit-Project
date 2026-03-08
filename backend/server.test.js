jest.mock('pg', () => {
    const mockQuery = jest.fn().mockResolvedValue({ rows: [{ count: '1' }] });
    return { Pool: jest.fn(() => ({ query: mockQuery })) };
});

jest.mock('nodemailer', () => ({
    createTransport: jest.fn(() => ({
        sendMail: jest.fn((_opts, cb) => cb(null, { response: 'OK' }))
    }))
}));

const request = require('supertest');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = require('./server');
const { Pool } = require('pg');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const mockPool = Pool.mock.results[0].value;

function makeToken(payload = { username: 'testuser', role: 'Admin' }) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
}

beforeAll(async () => {
    await new Promise(resolve => setTimeout(resolve, 100));
});

beforeEach(() => {
    mockPool.query.mockReset();
    mockPool.query.mockResolvedValue({ rows: [] });
});

describe('Authentication', () => {
    test('POST /api/login returns 400 without credentials', async () => {
        const res = await request(app).post('/api/login').send({});
        expect(res.status).toBe(400);
    });

    test('POST /api/login returns 401 for unknown user', async () => {
        mockPool.query.mockResolvedValue({ rows: [] });
        const res = await request(app)
            .post('/api/login')
            .send({ username: 'nobody', password: 'pass' });
        expect(res.status).toBe(401);
    });

    test('POST /api/login returns JWT token on success', async () => {
        const hash = await bcrypt.hash('testpass', 10);
        mockPool.query.mockResolvedValue({
            rows: [{ username: 'admin', password: hash, role: 'Admin' }]
        });
        const res = await request(app)
            .post('/api/login')
            .send({ username: 'admin', password: 'testpass' });
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('token');
        expect(res.body.success).toBe(true);

        const decoded = jwt.verify(res.body.token, JWT_SECRET);
        expect(decoded.username).toBe('admin');
        expect(decoded.role).toBe('Admin');
    });
});

describe('RBAC & Authorization', () => {
    test('POST /api/attack returns 401 without token', async () => {
        const res = await request(app)
            .post('/api/attack')
            .send({ attackType: 'keyscan' });
        expect(res.status).toBe(401);
    });

    test('GET /api/history returns 401 without token', async () => {
        const res = await request(app).get('/api/history');
        expect(res.status).toBe(401);
    });

    test('POST /api/attack denies high-risk modules for non-Admin users', async () => {
        const token = makeToken({ username: 'analyst', role: 'SOC Analyst' });
        const res = await request(app)
            .post('/api/attack')
            .set('Authorization', `Bearer ${token}`)
            .send({ attackType: 'getsystem', targetIp: '10.0.0.1' });
        expect(res.status).toBe(403);
    });

    test('POST /api/attack allows high-risk modules for Admin', async () => {
        const token = makeToken({ username: 'admin', role: 'Admin' });
        mockPool.query.mockResolvedValue({ rows: [] });
        const res = await request(app)
            .post('/api/attack')
            .set('Authorization', `Bearer ${token}`)
            .send({ attackType: 'getsystem', targetIp: '10.0.0.1' });
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('terminalOutput');
    });

    test('POST /api/attack allows standard modules for any authenticated user', async () => {
        const token = makeToken({ username: 'analyst', role: 'SOC Analyst' });
        mockPool.query.mockResolvedValue({ rows: [] });
        const res = await request(app)
            .post('/api/attack')
            .set('Authorization', `Bearer ${token}`)
            .send({ attackType: 'keyscan', targetIp: '10.0.0.1' });
        expect(res.status).toBe(200);
        expect(res.body.terminalOutput).toContain('keyscan_start');
    });
});

describe('Input Validation', () => {
    test('POST /api/attack rejects unknown attack type', async () => {
        const token = makeToken();
        const res = await request(app)
            .post('/api/attack')
            .set('Authorization', `Bearer ${token}`)
            .send({ attackType: 'does_not_exist' });
        expect(res.status).toBe(400);
    });

    test('POST /api/attack rejects missing attackType', async () => {
        const token = makeToken();
        const res = await request(app)
            .post('/api/attack')
            .set('Authorization', `Bearer ${token}`)
            .send({});
        expect(res.status).toBe(400);
    });

    test('POST /api/register/init rejects invalid email', async () => {
        const res = await request(app)
            .post('/api/register/init')
            .send({ username: 'test', email: 'not-an-email', password: 'Abcdef1!' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/email/i);
    });

    test('POST /api/register/init rejects short password', async () => {
        const res = await request(app)
            .post('/api/register/init')
            .send({ username: 'test', email: 'a@b.com', password: 'Ab1!' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/8 characters/i);
    });

    test('POST /api/register/init rejects password without uppercase', async () => {
        const res = await request(app)
            .post('/api/register/init')
            .send({ username: 'test', email: 'a@b.com', password: 'abcdefg1!' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/uppercase/i);
    });

    test('POST /api/register/init rejects password without special character', async () => {
        const res = await request(app)
            .post('/api/register/init')
            .send({ username: 'test', email: 'a@b.com', password: 'Abcdefg1' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/special/i);
    });

    test('POST /api/register/init rejects missing fields', async () => {
        const res = await request(app)
            .post('/api/register/init')
            .send({ username: 'test' });
        expect(res.status).toBe(400);
    });
});

describe('History Endpoint', () => {
    test('GET /api/history returns array with valid token', async () => {
        const token = makeToken();
        const mockRows = [
            { id: 1, username: 'admin', action: 'keyscan', target: '10.0.0.1', status: 'Success', executed_at: new Date() }
        ];
        mockPool.query.mockResolvedValue({ rows: mockRows });
        const res = await request(app)
            .get('/api/history')
            .set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body[0].action).toBe('keyscan');
    });
});

describe('Admin User Management', () => {
    test('GET /api/admin/users returns 403 for non-admin', async () => {
        const token = makeToken({ username: 'analyst', role: 'SOC Analyst' });
        const res = await request(app)
            .get('/api/admin/users')
            .set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(403);
    });

    test('GET /api/admin/users returns 401 without token', async () => {
        const res = await request(app).get('/api/admin/users');
        expect(res.status).toBe(401);
    });

    test('GET /api/admin/users returns user list for admin', async () => {
        const token = makeToken({ username: 'admin', role: 'Admin' });
        const mockUsers = [
            { id: 1, username: 'admin', email: 'admin@system.local', role: 'Admin', created_at: new Date() }
        ];
        mockPool.query.mockResolvedValue({ rows: mockUsers });
        const res = await request(app)
            .get('/api/admin/users')
            .set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(res.body[0].username).toBe('admin');
    });

    test('PUT /api/admin/users/:id/role rejects invalid role', async () => {
        const token = makeToken({ username: 'admin', role: 'Admin' });
        const res = await request(app)
            .put('/api/admin/users/2/role')
            .set('Authorization', `Bearer ${token}`)
            .send({ role: 'SuperUser' });
        expect(res.status).toBe(400);
    });

    test('PUT /api/admin/users/:id/role prevents changing own role', async () => {
        const token = makeToken({ username: 'admin', role: 'Admin' });
        mockPool.query.mockResolvedValue({ rows: [{ username: 'admin' }] });
        const res = await request(app)
            .put('/api/admin/users/1/role')
            .set('Authorization', `Bearer ${token}`)
            .send({ role: 'SOC Analyst' });
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/own role/i);
    });

    test('PUT /api/admin/users/:id/password rejects weak password', async () => {
        const token = makeToken({ username: 'admin', role: 'Admin' });
        const res = await request(app)
            .put('/api/admin/users/2/password')
            .set('Authorization', `Bearer ${token}`)
            .send({ newPassword: 'short' });
        expect(res.status).toBe(400);
    });

    test('DELETE /api/admin/users/:id prevents self-deletion', async () => {
        const token = makeToken({ username: 'admin', role: 'Admin' });
        mockPool.query.mockResolvedValue({ rows: [{ username: 'admin' }] });
        const res = await request(app)
            .delete('/api/admin/users/1')
            .set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(400);
        expect(res.body.error).toMatch(/own account/i);
    });

    test('DELETE /api/admin/users/:id returns 404 for non-existent user', async () => {
        const token = makeToken({ username: 'admin', role: 'Admin' });
        mockPool.query.mockResolvedValue({ rows: [] });
        const res = await request(app)
            .delete('/api/admin/users/999')
            .set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(404);
    });

    test('DELETE /api/admin/users/:id returns 403 for non-admin', async () => {
        const token = makeToken({ username: 'analyst', role: 'SOC Analyst' });
        const res = await request(app)
            .delete('/api/admin/users/2')
            .set('Authorization', `Bearer ${token}`);
        expect(res.status).toBe(403);
    });
});

describe('Public Endpoints', () => {
    test('GET /api/users/count returns count', async () => {
        mockPool.query.mockResolvedValue({ rows: [{ count: '5' }] });
        const res = await request(app).get('/api/users/count');
        expect(res.status).toBe(200);
        expect(res.body.count).toBe('5');
    });

    test('POST /api/heartbeat returns active user count', async () => {
        const res = await request(app)
            .post('/api/heartbeat')
            .send({ username: 'testuser' });
        expect(res.status).toBe(200);
        expect(res.body).toHaveProperty('activeCount');
    });
});
