# Regal Chocolate

A full stack e-commerce website for a chocolate brand, self-hosted on a Linux server.

🔗 [regalchocolate.in](https://regalchocolate.in/)

## About
An online store with user authentication, product management, and a PostgreSQL backend. 
Built with Python and Flask, and supported by a set of background services running on the same server.

## Built With
- Python / Flask
- PostgreSQL
- HTML / CSS / JavaScript
- Self-hosted on a Linux server

## Running Locally
```bash
git clone https://github.com/fjye1/chocolate_website
cd chocolate_website
pip install -r requirements.txt
```

You'll need a PostgreSQL database running and a `.env` file with your credentials. 
Then:
```bash
flask run
```

## Project Structure

This repo is part of a wider self-hosted setup made up of a few moving parts:

| Sub-Project | What it does |
|---|---|
| **E-commerce Store** | The main Flask web app |
| **PostgreSQL** | Database with automated triggers and scheduled backups |
| **Remote Worker** | Headless background worker handling emails, DB tasks, and cron jobs |
| **Monitor** | Checks server health and site uptime, fires email alerts if something breaks |