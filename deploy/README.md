# DigitalOcean Deployment

This deployment runs AIS-Detect as one FastAPI container that serves the built React frontend, with Caddy in front for HTTP/HTTPS.

## 1. Create the Droplet

Recommended starting point:

- Ubuntu 24.04 LTS
- Basic Droplet
- 2 GB RAM minimum, 4 GB RAM if you train larger datasets on the server
- Open ports 22, 80, and 443 in the DigitalOcean firewall

## 2. Install Docker on the Droplet

SSH into the Droplet, then run:

```bash
ssh -i /path/to/private_key root@your_droplet_ip
```

On Windows PowerShell, for example:

```powershell
ssh -i C:\Users\kimeon\fyp_droplet root@your_droplet_ip
```

Then install Docker inside the Droplet:

```bash
sudo apt update
sudo apt install -y ca-certificates curl git
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

## 3. Clone the Project

```bash
sudo mkdir -p /opt/ais-detect
sudo chown "$USER:$USER" /opt/ais-detect
git clone <your-repo-url> /opt/ais-detect
cd /opt/ais-detect
```

If the repo is private, use GitHub SSH keys or a deploy key.

## 4. Create Production Environment File

Create the real env file on the Droplet. Do not commit `deploy/ais.env`.

```bash
cp deploy/ais.env.example deploy/ais.env
python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
nano deploy/ais.env
```

Set at least:

- `AIS_SECRET_KEY`
- `AIS_ADMIN_PASSWORD`
- `AIS_ANALYST_PASSWORD`
- `AIS_CORS_ORIGINS`
- `AIS_SITE_ADDRESS`
- `CADDY_EMAIL`

For first testing by IP address, use:

```env
AIS_SITE_ADDRESS=:80
AIS_CORS_ORIGINS=http://your_droplet_ip
```

After pointing a domain to the Droplet, use:

```env
AIS_SITE_ADDRESS=ais-detect.example.com
AIS_CORS_ORIGINS=https://ais-detect.example.com
```

## 5. Start AIS-Detect

```bash
docker compose up -d --build
docker compose ps
```

Expected services:

```text
ais-api   Up ... healthy
caddy     Up ... 0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp
```

Open:

```text
http://your_droplet_ip
```

or your HTTPS domain once DNS is ready.

Expected routes:

```text
/       React frontend dashboard/login
/api    backend API landing page
/docs   Swagger API documentation
/health health check
```

## 6. Updating After Code Changes

On your laptop:

```bash
git add .
git commit -m "Update AIS-Detect"
git push
```

On the Droplet:

```bash
cd /opt/ais-detect
git pull
docker compose up -d --build
```

The SQLite database and trained model artifacts are stored in the Docker volume `ais_artefacts`, so rebuilding the app container does not erase them.

## 7. Run Your Laptop as the Sensor

The server-side interface dropdown shows the Droplet/container interfaces, such as `eth0`. That is expected. To monitor traffic from your laptop or lab machine, run the local sensor agent on that machine and let it send completed flow features to the deployed backend.

Prerequisites on the sensor machine:

- Python virtual environment with `requirements.txt` installed
- Administrator/root terminal for packet capture
- Windows only: Npcap installed
- A trained CICIDS2017 model on the deployed backend

List local capture interfaces:

```powershell
cd C:\Users\kimeon\Desktop\ais-backend
.\.venv\Scripts\activate
python scripts\local_sensor.py --api-base https://ais-detect-152-42-209-219.nip.io --list-interfaces
```

Run the sensor with the default Scapy interface:

```powershell
python scripts\local_sensor.py --api-base https://ais-detect-152-42-209-219.nip.io --username admin
```

Run the sensor with a selected interface:

```powershell
python scripts\local_sensor.py --api-base https://ais-detect-152-42-209-219.nip.io --username admin --interface "Wi-Fi"
```

The agent prompts for the AIS-Detect password, captures packets locally, converts them into CICIDS-compatible flows, and posts them to:

```text
POST /api/capture/ingest-flow
```

The dashboard should then show live counters and alerts from the remote sensor. Use the dashboard Stop button or `Ctrl+C` in the sensor terminal to stop the session.

## Troubleshooting

If SSH fails with `Permission denied (publickey)`, specify the private key, not the `.pub` file:

```powershell
ssh -i C:\Users\kimeon\fyp_droplet root@your_droplet_ip
```

If `cp deploy/ais.env.example deploy/ais.env` says the file does not exist, make sure you are inside the cloned project:

```bash
cd /opt/ais-detect
ls deploy
```

If `docker compose up -d --build` fails during `pip install`, inspect the build log:

```bash
docker compose build --no-cache ais-api 2>&1 | tee build.log
tail -n 80 build.log
```

`cicflowmeter` requires Python 3.12 or newer, so the deployment Dockerfile must use a Python 3.12 base image.

If `http://your_droplet_ip/` still shows the backend API page instead of the React app, confirm the latest code was pushed and pulled:

```bash
cd /opt/ais-detect
git pull
docker compose up -d --build
```

Then hard refresh the browser with `Ctrl+F5`. The backend landing page should be at `/api`, not `/`.

Useful log commands:

```bash
docker compose logs --tail=80 ais-api
docker compose logs --tail=80 caddy
```

## Notes

- Do not run live Scapy capture inside the cloud server unless you only want to inspect traffic to/from the Droplet.
- For the recommended FYP architecture, run packet capture on your laptop/lab sensor and send features/events to the deployed backend.
- `AIS_DEPLOYMENT_MODE=production` intentionally refuses to start if default seeded passwords are used.
