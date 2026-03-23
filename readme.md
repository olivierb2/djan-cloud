In 2026, if you want to free yourself from Google Drive or Microsoft 365, self-hosted options remain surprisingly limited. Nextcloud is essentially the only serious choice, with very few real alternatives. DjanCloud was born out of this frustration: a fast, lightweight Nextcloud-compatible server built with Django, offering the essential features without the complexity of the PHP stack.

What is working so far:

- Login page, user management with simple role.
- Web UI to browse files and folders.
- Simple shared folder
- Login with official Nextcloud client and full synchronisation
- Browsable files over webdav.
- Collaborative markdown editor
- Shared calendars with CalDAV support
- Shared contacts with CardDAV support

What I'm planning to do:

- Integrate OnlyOffice or Collabora Office

Any requests or pull requests are welcome.

    This is draft project, don't expect to have it running in production !!

![screenshot](screenshot.png)

# How to start with Docker Compose

```
cp .env.example .env
docker compose up --build
```

The application will be available at http://localhost:8080

To create the first admin user:

```
docker compose exec -ti web python manage.py createsuperuser
```

# How to start the development server (without Docker)

Install system packages (Debian/Ubuntu)

```
apt-get install python3 python3-pip python3-venv git nodejs npm
```

Clone this repository and create virtual env

```
git clone https://github.com/olivierb2/djan-cloud
cd djan-cloud
python3 -m venv venv
. ./venv/bin/activate
pip install -r requirements.txt
```

Build the frontend

```
cd frontend
npm install
npm run build
cd ..
```

Configure the environment

```
cp .env.example .env
```

Create database and first admin user

```
python3 manage.py migrate
python3 manage.py createsuperuser
```

Run the development server

```
python3 manage.py runserver
```
