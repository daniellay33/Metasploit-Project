# MSF Platform - Project Context

## AWS Setup

- **Region:** il-central-1 (Israel)
- **EC2 Instance:** i-075e1e8ac80620d54 (t3.large, running)
- **Public IP:** 51.84.194.94 (static via Elastic IP)
- **ECS Cluster:** msf-platform
- **ECS Service:** msf-platform-service
- **Current Task Definition:** msf-platform:18
- **RDS Endpoint:** msf-platform-db.chiuq024ys8x.il-central-1.rds.amazonaws.com
- **Domain:** msf-platform.xyz (GoDaddy, pointing to CloudFront)
- **CloudFront:** HTTPS termination, points to EC2:80 via nginx
- **ACM Certificate:** us-east-1 (required for CloudFront)

## AWS CLI

AWS CLI is at: `C:\Program Files\Amazon\AWSCLIV2\aws.exe`

Always add to PATH first:
```powershell
$env:PATH += ";C:\Program Files\Amazon\AWSCLIV2"
```

Common commands:
```powershell
# Check service status
aws ecs describe-services --cluster msf-platform --services msf-platform-service --region il-central-1 --query "services[0].{running:runningCount,pending:pendingCount,taskDef:taskDefinition}"

# Redeploy (force new deployment)
aws ecs update-service --cluster msf-platform --service msf-platform-service --task-definition msf-platform:XX --force-new-deployment --deployment-configuration "minimumHealthyPercent=0,maximumPercent=200" --region il-central-1

# Register new task definition
aws ecs register-task-definition --cli-input-json file://C:\Users\Rafael\Desktop\Metasploit-Project\Metasploit-Project\ecs-task-definition.json --region il-central-1 --query "taskDefinition.revision"

# Stop current task (forces restart)
aws ecs stop-task --cluster msf-platform --task $(aws ecs list-tasks --cluster msf-platform --service-name msf-platform-service --region il-central-1 --query "taskArns[0]" --output text) --region il-central-1

# Run command on EC2 via SSM (use base64 for complex scripts)
$script = @'
CONT=$(docker ps --filter name=victimtarget --format '{{.Names}}' | head -1)
echo $CONT
'@
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($script))
$cmdId = aws ssm send-command --instance-ids "i-075e1e8ac80620d54" --document-name "AWS-RunShellScript" --parameters "{`"commands`":[`"echo $encoded | base64 -d | bash`"]}" --region il-central-1 --query "Command.CommandId" --output text
Start-Sleep -Seconds 15
aws ssm get-command-invocation --command-id "$cmdId" --instance-id "i-075e1e8ac80620d54" --region il-central-1 --query "{Status:Status,Out:StandardOutputContent,Err:StandardErrorContent}" --output json
```

## Docker Hub

- **Username:** danieladoc
- **Backend image:** danieladoc/msf-backend:latest
- **Frontend image:** danieladoc/msf-frontend:latest
- **Victim image:** danieladoc/msf-victim:latest

Build & deploy workflow:
```powershell
# Build
cd C:\Users\Rafael\Desktop\Metasploit-Project\Metasploit-Project\backend
docker build -t danieladoc/msf-backend:latest .
docker push danieladoc/msf-backend:latest

cd C:\Users\Rafael\Desktop\Metasploit-Project\Metasploit-Project\frontend
docker build -t danieladoc/msf-frontend:latest .
docker push danieladoc/msf-frontend:latest

cd C:\Users\Rafael\Desktop\Metasploit-Project\Metasploit-Project\victim
docker build -t danieladoc/msf-victim:latest .
docker push danieladoc/msf-victim:latest

# Register + deploy
$env:PATH += ";C:\Program Files\Amazon\AWSCLIV2"
$rev = aws ecs register-task-definition --cli-input-json file://C:\Users\Rafael\Desktop\Metasploit-Project\Metasploit-Project\ecs-task-definition.json --region il-central-1 --query "taskDefinition.revision" --output text
aws ecs update-service --cluster msf-platform --service msf-platform-service --task-definition "msf-platform:$rev" --force-new-deployment --deployment-configuration "minimumHealthyPercent=0,maximumPercent=200" --region il-central-1
```

## Project Structure

```
Metasploit-Project/
├── backend/
│   ├── server.js          # Main backend (Node.js/Express)
│   ├── package.json
│   └── Dockerfile
├── frontend/
│   ├── index.html         # Single-page app (Tailwind CSS)
│   ├── nginx.conf         # Serves on port 8080
│   └── Dockerfile
├── victim/
│   ├── Dockerfile         # linuxserver/webtop ubuntu-xfce
│   └── autostart.sh       # Runs at container init (s6-overlay)
└── ecs-task-definition.json
```

## Container Architecture (host network mode)

```
EC2 Host (nginx on port 80/443)
  ├── /api/*       → backend:3000
  ├── /victim/*    → victim:3002
  └── /*           → frontend:8080

Containers:
  - backend       port 3000   Node.js API
  - frontend      port 8080   nginx static
  - victim_target port 3002   linuxserver/webtop (XFCE desktop stream)
                  port 3003   HTTPS victim desktop
  - metasploit    (interactive)
```

## Database

- **Type:** Amazon RDS PostgreSQL
- **Auth:** IAM role (no password) — uses @aws-sdk/rds-signer
- **DB name:** metasploit_db
- **User:** msf_admin (has rds_iam role in PostgreSQL)
- **Tables:** users, scan_history

## Key Backend Endpoints

- `POST /api/login` — JWT auth
- `POST /api/attack` — run exploit module (attackType in body)
- `POST /api/victim/open-youtube` — open YouTube on victim via docker exec
- `GET /api/loot/:filename?token=JWT` — serve loot files (video/audio)
- `POST /api/exploit/import` — import exploit from URL

## Victim Container Details

- Base image: `linuxserver/webtop:ubuntu-xfce`
- Real Chromium binary: `/usr/bin/chromium` (NOT chromium-browser — that's a snap stub)
- Display: `:1`
- User: `abc` (uid=1000)
- Home: `/config`
- XDG_RUNTIME_DIR: `/run/user/1000`
- PulseAudio: enabled (SELKIES_AUDIO=true)

To run commands as abc user with display:
```bash
docker exec -u abc -e DISPLAY=:1 -e HOME=/config -e XDG_RUNTIME_DIR=/run/user/1000 <container> <cmd>
```

To get victim container name:
```bash
docker ps --filter 'name=victimtarget' --format '{{.Names}}' | head -1
```

## Pending Issues

### 1. Open YouTube button not working
- Button exists in Exploit Engine tab (red button top-right)
- Backend endpoint: `POST /api/victim/open-youtube`
- Current command uses `docker exec -d` with `/usr/bin/chromium`
- Problem: chromium might be crashing silently — need to capture error output
- **Next step:** Change `docker exec -d` to regular `docker exec` with log capture and return the log in the response so we can see the real error

### 2. Screen recording video not showing in browser
- Backend returns `videoFileName` instead of base64 (fixed - avoids size limit)
- Frontend fetches from `/api/loot/:filename?token=JWT`
- Needs testing after YouTube is working (so there's movement in the video)

### 3. Audio recording
- Returns simulated WAV if PulseAudio capture fails
- Fixed mic command to use `.monitor` source (captures system audio)
- Needs testing after YouTube is working (so there's audio to capture)

## ECS Task Definition env vars (victim container)

```json
SELKIES_FRAMERATE=15
SELKIES_VIDEO_BITRATE=500
SELKIES_AUDIO=true
SELKIES_AUDIO_BITRATE=128
PULSE_RUNTIME_PATH=/run/user/1000/pulse
CUSTOM_PORT=3002
CUSTOM_HTTPS_PORT=3003
```

## Exploit Modules (in UI)

10 clickable cards in Exploit Engine tab:
1. Reverse Shell — simulated
2. Keylogger — simulated  
3. Screenshot — REAL (scrot via docker exec -u abc)
4. Webcam Snap — simulated
5. Mic Record — real attempt, fallback to simulated WAV
6. Screen Record — REAL (ffmpeg x11grab, returns videoFileName URL)
7. Get SYSTEM — simulated
8. Hashdump — simulated
9. Persistence — simulated
10. Exfiltrate — simulated

## nginx on EC2 host

Config at: `/etc/nginx/conf.d/default.conf`
Handles routing from port 80 → internal containers.
Port 4443 has self-signed cert proxying to victim HTTPS (port 3003) for WebSocket.

To update nginx config via SSM use base64 encoding to avoid shell variable expansion issues.
