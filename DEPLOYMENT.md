# 🚀 Deploying LinkArmor Live to the Web

LinkArmor is completely prepared for live cloud deployment. All necessary production files have been created:
- [`requirements.txt`](file:///c:/Users/SERVER/Downloads/AI-based-phishing-main/requirements.txt) — Production Python dependencies.
- [`Procfile`](file:///c:/Users/SERVER/Downloads/AI-based-phishing-main/Procfile) — Web process runner with Gunicorn.
- [`render.yaml`](file:///c:/Users/SERVER/Downloads/AI-based-phishing-main/render.yaml) — Native Render infrastructure-as-code blueprint.
- [`Dockerfile`](file:///c:/Users/SERVER/Downloads/AI-based-phishing-main/Dockerfile) — Universal Docker container definition for Railway, Fly.io, or HuggingFace Spaces.
- [`app.py`](file:///c:/Users/SERVER/Downloads/AI-based-phishing-main/app.py) — Configured with dynamic `$PORT` binding (`0.0.0.0`).

---

## Option 1: 🌟 Render.com (Recommended — 100% Free & Easy)

1. Push this project to your GitHub account:
   ```bash
   git init
   git add .
   git commit -m "Initial commit of LinkArmor"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/linkarmor.git
   git push -u origin main
   ```
2. Go to **[Render.com](https://render.com/)** and sign in with GitHub.
3. Click **New +** $\rightarrow$ **Web Service**.
4. Select your `linkarmor` repository.
5. Set:
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
6. Click **Create Web Service**.
7. In ~2 minutes, your website will be live at `https://linkarmor-xxxx.onrender.com`!

---

## Option 2: 🚂 Railway.app (Instant 1-Click Deploy)

1. Push your code to GitHub (as above).
2. Go to **[Railway.app](https://railway.app/)** and sign in with GitHub.
3. Click **New Project** $\rightarrow$ **Deploy from GitHub Repo**.
4. Select `linkarmor`. Railway will auto-detect the `Procfile` / `requirements.txt` and provide a public HTTPS URL.

---

## Option 3: 🤗 Hugging Face Spaces (Free Cloud for ML Apps)

1. Go to **[huggingface.co/spaces](https://huggingface.co/spaces)**.
2. Click **Create new Space**.
3. Choose **Docker** (Blank) or **Gradio**.
4. Clone and push your files. Hugging Face will build the container using our [`Dockerfile`](file:///c:/Users/SERVER/Downloads/AI-based-phishing-main/Dockerfile) and host it permanently for free.

---

## Option 4: ⚡ Instant Live Public URL Right Now (Ngrok / Cloudflare Tunnel)

If you want to share a live working link right this second directly from your machine:
```bash
# Using Cloudflare Tunnel (no account required):
npx cloudflared tunnel --url http://127.0.0.1:5000
```
This generates a temporary public HTTPS link (e.g. `https://xxxx.trycloudflare.com`) accessible from any device or phone worldwide!
