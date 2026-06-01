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
docker compose logs -f ais-api
```

Open:

```text
http://your_droplet_ip
```

or your HTTPS domain once DNS is ready.

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

## Notes

- Do not run live Scapy capture inside the cloud server unless you only want to inspect traffic to/from the Droplet.
- For the recommended FYP architecture, run packet capture on your laptop/lab sensor and send features/events to the deployed backend.
- `AIS_DEPLOYMENT_MODE=production` intentionally refuses to start if default seeded passwords are used.
