import 'dotenv/config';
import express from 'express';
import http from 'http';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import { Server as SocketIOServer } from 'socket.io';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import fs from 'fs';
import path from 'path';

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
	cors: {
		origin: process.env.FRONTEND_URL || 'http://localhost:3000',
		credentials: true,
	},
});

const prisma = new PrismaClient();

app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(helmet());
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'dev-cookie-secret'));
app.use(morgan('dev'));
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

// Health
app.get('/health', (_req, res) => {
	res.json({ ok: true, uptime: process.uptime() });
});

// Auth
function generateToken(userId: string) {
	const secret = process.env.JWT_SECRET || 'dev-jwt-secret';
	return jwt.sign({ sub: userId }, secret, { expiresIn: '7d' });
}

app.post('/api/auth/register', async (req, res) => {
	const { email, password, name } = req.body || {};
	if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
	const existing = await prisma.user.findUnique({ where: { email } });
	if (existing) return res.status(409).json({ error: 'Email already registered' });
	const passwordHash = await bcrypt.hash(password, 10);
	const user = await prisma.user.create({ data: { email, password: passwordHash, name } });
	const token = generateToken(user.id);
	res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role }, token });
});

app.post('/api/auth/login', async (req, res) => {
	const { email, password } = req.body || {};
	if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
	const user = await prisma.user.findUnique({ where: { email } });
	if (!user) return res.status(401).json({ error: 'Invalid credentials' });
	const ok = await bcrypt.compare(password, user.password);
	if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
	const token = generateToken(user.id);
	res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role }, token });
});

// Simple auth middleware
function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
	const header = req.headers.authorization;
	if (!header) return res.status(401).json({ error: 'Missing Authorization header' });
	const token = header.replace('Bearer ', '');
	try {
		const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-jwt-secret') as { sub: string };
		(req as any).userId = payload.sub;
		next();
	} catch {
		return res.status(401).json({ error: 'Invalid token' });
	}
}

// File uploads (local storage; can be swapped to S3 later)
const uploadDir = process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
const upload = multer({ dest: uploadDir });

app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
	if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
	res.json({ file: { originalName: req.file.originalname, path: req.file.path, size: req.file.size } });
});

// User profile
app.get('/api/me', requireAuth, async (req, res) => {
	const userId = (req as any).userId as string;
	const user = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, email: true, name: true, role: true, createdAt: true } });
	res.json({ user });
});

io.on('connection', (socket) => {
	socket.emit('welcome', { message: 'Connected' });
});

const port = Number(process.env.PORT || 3001);
server.listen(port, () => {
	console.log(`API listening on http://localhost:${port}`);
});