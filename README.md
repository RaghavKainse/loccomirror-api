# loccoMirror Authentication & User Backend

Node.js, Express, MongoDB (Mongoose), and JWT authentication service ready for Vercel Serverless deployment and loccoMirror desktop client integration.

---

## 🚀 Quick Deploy to Vercel

### Option A: Deploy via GitHub (Recommended)
1. Push this `backend` folder to a new GitHub repository (e.g., `https://github.com/RaghavKainse/loccomirror-api`).
2. Go to [Vercel Dashboard](https://vercel.com/new).
3. Import the repository.
4. Add the following **Environment Variables** in Vercel:
   - `MONGODB_URI`: Your MongoDB Atlas connection string (`mongodb+srv://<user>:<password>@cluster0.mongodb.net/loccomirror?retryWrites=true&w=majority`).
   - `JWT_SECRET`: Any secure random key.
5. Click **Deploy**. Vercel will provide you with a live URL (e.g. `https://loccomirror-api.vercel.app`).

### Option B: Deploy via Vercel CLI
```bash
cd backend
npx vercel
```
Follow prompts, configure environment variables in Vercel project settings, and deploy to production with:
```bash
npx vercel --prod
```

---

## 📡 API Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :---: |
| `POST` | `/api/auth/signup` | Register new user account (`name`, `email`, `password`) | No |
| `POST` | `/api/auth/login` | Log in user (`email`, `password`) and receive JWT token | No |
| `GET` | `/api/auth/me` | Fetch authenticated user profile & verify session | Yes (`Bearer <token>`) |
| `PUT` | `/api/auth/profile` | Update profile (`name`, `avatar`) | Yes (`Bearer <token>`) |
| `GET` | `/api/auth/health` | Healthcheck indicator | No |

---

## 💻 Local Development

1. Install dependencies:
   ```bash
   npm install
   ```
2. Copy `.env.example` to `.env` and configure `MONGODB_URI` and `JWT_SECRET`.
3. Start local development server:
   ```bash
   npm start
   ```
4. Access API at `http://localhost:5000`.
