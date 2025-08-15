### Backend (Express + Prisma)

- Copy `.env.example` to `.env` and fill values
- Install deps: `npm install`
- Generate Prisma client: `npm run prisma:generate`
- Create DB and run initial migration: `npm run prisma:migrate`
- Start dev server: `npm run dev`

API
- `GET /health` health check
- `POST /api/auth/register { email, password, name? }`
- `POST /api/auth/login { email, password }`
- `GET /api/me` with `Authorization: Bearer <token>`
- `POST /api/upload` multipart `file`, with `Authorization: Bearer <token>`