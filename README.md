# 🛡️ Mini Internal PKI Certificate Manager - Web App

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Django](https://img.shields.io/badge/Django-4.x-success.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Stars](https://img.shields.io/github/stars/ahasansubri/cert_manager.svg?style=social)](https://github.com/ahasansubri/cert_manager/stargazers)
[![Forks](https://img.shields.io/github/forks/ahasansubri/cert_manager.svg?style=social)](https://github.com/ahasansubri/cert_manager/network/members)
[![Issues](https://img.shields.io/github/issues/ahasansubri/cert_manager.svg)](https://github.com/ahasansubri/cert_manager/issues)

**Mini Internal PKI Certificate Manager** is a Django-based web application designed for managing internal certificate lifecycles — including certificate issuance, revocation, CRL generation, and OCSP response serving for VPN authentication systems.

---

## ⚙️ Core Features

### 🔐 Certificate Management
- Create and manage multiple **Certificate Authorities (CAs)**
- Issue, view, and revoke certificates (like pfSense Cert Manager)
- Export certificates in multiple formats (`.crt`, `.key`, `.p12`)

### 🚫 Certificate Revocation
- Manual revocation directly from the web UI  
- Automatic **CRL (Certificate Revocation List)** regeneration  
- Downloadable CRL for firewall and VPN integrations  

### 🧩 OCSP Responder
- Built-in **OCSP responder** for real-time certificate validation  
- Tested successfully with **Palo Alto GlobalProtect**  
- Planned future testing with **Cisco ASA**, **FortiClient**, and **OpenVPN**

---

## 🧰 Tech Stack

| Component | Description |
|------------|--------------|
| **Framework** | Django (Python 3.10+) |
| **Web Server** | Apache2 + `mod_wsgi` |
| **Database** | SQLite (lightweight, built-in) |
| **Frontend** | Bootstrap 5 |
| **Supported OS** | Ubuntu 22.04+ |

---

## 🚀 One-Command Deployment (Recommended)

You can fully deploy this application on any fresh Ubuntu server using the included **automated deployment script**.

### 🪄 Run the Deployment Script

#### Step 1: Create Script file.
```
nano deploy_crlserver.sh
```
#### Step 2: Copy and Paste the following script to the file and save it.
```
#!/usr/bin/env bash
set -euo pipefail

# =======================
# Configurable defaults
# =======================
DEFAULT_REPO_URL="https://github.com/ahasansubri/cert_manager.git"
DEFAULT_BRANCH="main"
DEFAULT_APP_DIR="/home/crlserver"
DEFAULT_SERVER_NAME="10.1.20.168"   # prompt below

# =======================
# Prompts
# =======================
read -rp "Git repository URL [${DEFAULT_REPO_URL}]: " REPO_URL
REPO_URL="${REPO_URL:-$DEFAULT_REPO_URL}"

read -rp "Git branch [${DEFAULT_BRANCH}]: " BRANCH
BRANCH="${BRANCH:-$DEFAULT_BRANCH}"

read -rp "Application directory [${DEFAULT_APP_DIR}]: " APP_DIR
APP_DIR="${APP_DIR:-$DEFAULT_APP_DIR}"

read -rp "Apache ServerName (IP or DNS) [${DEFAULT_SERVER_NAME}]: " SERVER_NAME
SERVER_NAME="${SERVER_NAME:-$DEFAULT_SERVER_NAME}"

# =======================
# Derived paths
# =======================
VENV_DIR="${APP_DIR}/venv"
WSGI_FILE="${APP_DIR}/crlserver/wsgi.py"
VHOST_FILE="/etc/apache2/sites-available/crlserver.conf"
SERVERNAME_CONF="/etc/apache2/conf-available/servername.conf"
DB_FILE="${APP_DIR}/db.sqlite3"

# =======================
# Helpers
# =======================
die() { echo "ERROR: $*" >&2; exit 1; }

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    die "Please run this script with sudo or as root."
  fi
}

apt_install() {
  local pkgs=("$@")
  echo "Installing packages: ${pkgs[*]} ..."
  apt-get update -y
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
}

ensure_pkg() {
  dpkg -s "$1" >/dev/null 2>&1 || apt_install "$1"
}

apache_reload_or_start() {
  if systemctl is-active --quiet apache2; then
    systemctl reload apache2
  else
    systemctl start apache2
  fi
}

# =======================
# Main
# =======================
ensure_root

# 1) Install prerequisites
ensure_pkg "ca-certificates"
ensure_pkg "curl"
ensure_pkg "git"
ensure_pkg "python3-venv"
ensure_pkg "python3-pip"
ensure_pkg "apache2"
ensure_pkg "libapache2-mod-wsgi-py3"

# 2) Prepare app dir
mkdir -p "$APP_DIR"
# Give the invoking user ownership for dev/maintenance (adjust if desired)
chown -R "$SUDO_USER:${SUDO_USER:-$USER}" "$APP_DIR" || true

# 3) Clone or update public repo over HTTPS
if [[ -d "${APP_DIR}/.git" ]]; then
  echo "Existing Git repository detected. Updating ..."
  sudo -u "${SUDO_USER:-$USER}" git -C "$APP_DIR" config --global --add safe.directory "$APP_DIR" || true
  sudo -u "${SUDO_USER:-$USER}" git -C "$APP_DIR" remote set-url origin "$REPO_URL" || true
  sudo -u "${SUDO_USER:-$USER}" git -C "$APP_DIR" fetch --all --prune
  sudo -u "${SUDO_USER:-$USER}" git -C "$APP_DIR" checkout "$BRANCH"
  sudo -u "${SUDO_USER:-$USER}" git -C "$APP_DIR" reset --hard "origin/${BRANCH}"
else
  echo "Cloning ${REPO_URL} into ${APP_DIR} ..."
  rm -rf "$APP_DIR"/*
  sudo -u "${SUDO_USER:-$USER}" git clone --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

# 4) Python virtualenv
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "Creating virtualenv at ${VENV_DIR} ..."
  sudo -u "${SUDO_USER:-$USER}" python3 -m venv "$VENV_DIR"
fi
chmod +x "${VENV_DIR}/bin/pip" || true

# 5) Install requirements
echo "Installing Python dependencies ..."
sudo -u "${SUDO_USER:-$USER}" bash -lc "
  source '$VENV_DIR/bin/activate'
  pip install --upgrade pip
  pip install -r '$APP_DIR/requirements.txt'
"

# 6) Run migrations and collectstatic
echo "Running Django migrations & collectstatic ..."
sudo -u "${SUDO_USER:-$USER}" bash -lc "
  cd '$APP_DIR'
  source '$VENV_DIR/bin/activate'
  python manage.py migrate --noinput
  python manage.py collectstatic --noinput
"

# 7) Create default superuser (username=default / password=default)
echo "Creating default Django superuser (username=default / password=default)..."
sudo -u "${SUDO_USER:-$USER}" bash -lc "
  cd '$APP_DIR'
  source '$VENV_DIR/bin/activate'
  echo \"from django.contrib.auth import get_user_model; User = get_user_model();
u='default'
if not User.objects.filter(username=u).exists():
    User.objects.create_superuser(u, 'admin@example.com', 'default')\" | python manage.py shell
"

# 8) Fix log viewing permissions (www-data -> adm group)
usermod -aG adm www-data || true

# 9) Fix SQLite permissions (prevent read-only DB)
echo "Fixing SQLite database write permissions ..."
systemctl stop apache2 || true
if [[ -f "$DB_FILE" ]]; then
  chown www-data:www-data "$DB_FILE" 2>/dev/null || true
  chown www-data:www-data "$DB_FILE"* 2>/dev/null || true
  chmod 664 "$DB_FILE" 2>/dev/null || true
  chmod 664 "$DB_FILE"* 2>/dev/null || true
fi
# Directory that holds the DB must be writable by www-data (for WAL/journal)
chown www-data:www-data "$APP_DIR"
chmod 775 "$APP_DIR"
# Ensure media is writable
mkdir -p "${APP_DIR}/media"
chown -R www-data:www-data "${APP_DIR}/media"
chmod -R 775 "${APP_DIR}/media"

# 10) Apache vhost
echo "Writing Apache vhost to ${VHOST_FILE} ..."
cat > "$VHOST_FILE" <<CONF
<VirtualHost *:80>
    ServerName ${SERVER_NAME}

    # Run Django via mod_wsgi using your virtualenv
    WSGIDaemonProcess crlserver python-home=${VENV_DIR} python-path=${APP_DIR}
    WSGIProcessGroup crlserver
    WSGIApplicationGroup %{GLOBAL}
    WSGIScriptAlias / ${WSGI_FILE}

    # Static & media (served by Apache)
    Alias /static/ ${APP_DIR}/staticfiles/
    Alias /media/  ${APP_DIR}/media/

    <Directory ${APP_DIR}/crlserver>
        <Files wsgi.py>
            Require all granted
        </Files>
    </Directory>

    <Directory ${APP_DIR}/staticfiles>
        Require all granted
    </Directory>

    <Directory ${APP_DIR}/media>
        Require all granted
    </Directory>

    # Optional hardening headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"

    ErrorLog \${APACHE_LOG_DIR}/crlserver_error.log
    CustomLog \${APACHE_LOG_DIR}/crlserver_access.log combined
</VirtualHost>
CONF

# 11) Global Apache ServerName
echo "Setting global Apache ServerName to ${SERVER_NAME} ..."
cat > "$SERVERNAME_CONF" <<CONF
ServerName ${SERVER_NAME}
CONF
a2enconf servername >/dev/null || true

# 12) Enable Apache site and modules
a2enmod wsgi headers >/dev/null || true
a2ensite crlserver >/dev/null || true
a2dissite 000-default >/dev/null || true

echo "Checking Apache configuration ..."
apache2ctl configtest

echo "Reloading/Starting Apache ..."
apache_reload_or_start

# 13) Final summary
echo
echo "=========================================================="
echo " Deployment finished!"
echo " App path:     ${APP_DIR}"
echo " Venv:         ${VENV_DIR}"
echo " WSGI:         ${WSGI_FILE}"
echo " ServerName:   ${SERVER_NAME}"
echo " Repo:         ${REPO_URL}"
echo " Superuser:    username=default  password=default"
echo " Logs:         /var/log/apache2/crlserver_error.log"
echo "               /var/log/apache2/crlserver_access.log"
echo " Visit:        http://${SERVER_NAME}/"
echo "=========================================================="
```
#### Step 3: Make the script file executable.
```
chmod +x deploy_crlserver.sh
```
#### Step 4: Run the script.
```
sudo ./deploy_crlserver.sh
```
#### Step 5: You’ll be prompted for:
- Git repository URL (default: https://github.com/ahasansubri/cert_manager.git)
- Branch name (default: main)
- Application directory (default: /home/crlserver)
- Apache ServerName (your server’s IP or hostname)

### ✨ What the Script Does

- Installs all required packages (Python, Apache2, mod_wsgi, etc.)
- Clones the repository
- Sets up Python virtual environment
- Installs project dependencies
- Applies database migrations
- Collects static files
- Creates default Django superuser:
- Username: default
- Password: default
- Configures Apache virtual host
- Fixes permissions (logs, SQLite, media)
- Starts Apache automatically

### ✅ When Finished, You’ll See
- Deployment finished!
- App path: /home/crlserver
- Venv: /home/crlserver/venv
- ServerName:
- Superuser: username=default password=default
- Visit: 

## 🧪 Tested Environment

| Environment | Status |
|--------------|--------|
| **Ubuntu 22.04 / 24.04** | ✅ |
| **Apache2 + mod_wsgi** | ✅ |
| **Python 3.10+** | ✅ |
| **Palo Alto GlobalProtect** | ✅ Tested |
| **Cisco ASA** | 🔜 Planned |
| **FortiClient SSL VPN** | 🔜 Planned |
| **OpenVPN** | 🔜 Planned |

---

## 📫 Contact & Connect

Pull requests are welcome!
I'm always open to collaboration, knowledge sharing, and cybersecurity discussions.  
Feel free to reach out or connect with me through the following:

- **📧 Email:** [ahasansubri@gmail.com](mailto:ahasansubri@gmail.com)
- **💼 LinkedIn:** [Md Ahasan Subri](https://bd.linkedin.com/in/md-ahasan-subri)

If you found this project useful, please ⭐ the repository — your support means a lot!


