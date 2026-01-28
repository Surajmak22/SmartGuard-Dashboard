# 🚀 Deployment Guide: SmartGuard AI Dashboard

This project is **Docker-Ready** for production deployment.
You can deploy it for free (or cheap) on **Railway** or **Render** in less than 5 minutes.

## Option 1: Railway.app (Recommended)
**Pros:** Fastest setup, auto-HTTPS, reliable.

1.  **Push to GitHub**: Ensure this code is pushed to your GitHub repository.
2.  **Login**: Go to [Railway.app](https://railway.app/) and login with GitHub.
3.  **New Project**: Click **"New Project"** -> **"Deploy from GitHub repo"**.
4.  **Select Repo**: Choose your `AI-Driven-Threat-Detection-System` repo.
5.  **Deploy**: Railway will automatically detect the `Dockerfile` and start building.
    - *No configuration needed.*
6.  **Domain**: Once deployed, go to **Settings** -> **Domains** to generate a public URL (e.g., `smartguard-production.up.railway.app`) or connect your own domain.

## Option 2: Render.com
**Pros:** Solid free tier (spins down on free, continuous on paid).

1.  **Login**: Go to [Render.com](https://render.com/).
2.  **New Web Service**: Click **"New +"** -> **"Web Service"**.
3.  **Connect Repo**: Select your GitHub repo.
4.  **Runtime**: Select **"Docker"** (It should detect the Dockerfile).
5.  **Plan**: Choose Free or Starter ($7/mo).
6.  **Create**: Click "Create Web Service".

## Troubleshooting
- **Port**: If asked, the Internal Port is `8501`.
- **Logs**: Check the "Deploy Logs" tab if the build fails.
- **Python Version**: The Dockerfile uses Python 3.10.

---
**Verified for Production 2026**
