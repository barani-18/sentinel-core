

# Sentinel-Core: Autonomous Cloud-Native SOC Analyst

A real-time cybersecurity simulation environment that emulates a modern Security Operations Center (SOC) with AI-powered threat detection, autonomous response capabilities, and live database syncing.

  

## 🎯 Overview

Sentinel-Core simulates a cloud-native SOC where analysts (or autonomous agents) monitor security alerts, investigate threats, and take defensive actions across a distributed infrastructure. The platform features realistic alert telemetry, live WebSocket synchronization, host compromise modeling, and an autonomous AI agent capable of self-driving threat mitigation.

## ✨ Features

### 🔐 Secure Login Portal

  - **Supabase Authentication** for secure, production-ready login sessions.
  - **Role-based user metadata mapping** (Analyst, Senior Analyst, SOC Lead, Admin).
  - **Beautiful glassmorphism UI** with animated gradient backgrounds.

### 🤖 Autonomous AI Agent (Auto-Play)

  - **Self-Driving SOC**: Toggle "Auto-Play" to watch the AI automatically resolve, escalate, block, or isolate threats based on severity and threat signatures.
  - **Realistic Threat Generation**: Automatically injects MITRE ATT\&CK telemetry (e.g., `Ransomware.WannaCry`, `SQL Injection Payload`) targeting realistic cloud infrastructure (e.g., `ip-10-0-12-32.ec2.internal`).

### 📊 SOC Dashboard

1.  **Alerts Panel**

      - Real-time alert table with ID, severity, type, confidence, status.
      - Color-coded severity (Red=High, Yellow=Medium, Green=Low).
      - Live updates pushed directly from PostgreSQL via WebSockets.

2.  **System Metrics**

      - Compromised hosts counter (Tracking 12 simulated cloud instances).
      - Anomaly score (0-100%).
      - CPU usage monitoring (Cluster average).
      - Threat level gauge (Dynamic Red/Amber/Green scaling).

3.  **Action Controls**

      - Investigate Alert (Gathers intel).
      - Block IP (Mitigates active network attacks).
      - Isolate Host (Contains compromised instances).
      - Ignore Alert (Triage false positives).
      - Escalate (Push to Tier-2 review).
      - Resolve (Close the ticket).

4.  **Visualization**

      - System Health Timeline (Recharts) plotting dual-axis Anomalies vs. Threats.
      - Host Risk Distribution Heatmap.
      - Real-time drawing charts with fluid transitions.

5.  **Activity Logs**

      - Timestamped action history.
      - Clear distinction between Human actions and AI/Agent actions.
      - Color-coded by severity (Error, Warning, Success, Info).

## 🏗️ Architecture

```text
Frontend (React + Vite)                Backend (Supabase BaaS)
     │                                       │
     ├─ Login Portal          <─── Auth ───> ├─ Supabase Authentication (JWT)
     ├─ Operations Center     <── Live ───>  ├─ PostgreSQL Database
     ├─ Analytics Center      <── Sync ───>  ├─ WebSockets (pg_changes)
     └─ Autonomous AI Engine                 └─ Row Level Security (RLS)
```

## 🚀 Quick Start (Local Development)

### 1\. Supabase Setup (Backend)

1.  Create a free account at [Supabase.com](https://supabase.com).
2.  Create a new project.
3.  In the SQL Editor, create your tables:

<!-- end list -->

```sql
CREATE TABLE alerts (id SERIAL PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT NOW(), type TEXT, severity TEXT, confidence FLOAT, srcip TEXT, host TEXT, status TEXT);
CREATE TABLE logs (id SERIAL PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT NOW(), msg TEXT, kind TEXT);
```

4.  Disable **Row Level Security (RLS)** for both tables so the dashboard can read/write freely.
5.  Create a User in the **Authentication** tab (e.g., `analyst@sentinel.com` / `soc2024`).

### 2\. Frontend Setup

```bash
git clone https://github.com/YOUR_USERNAME/sentinel-core.git
cd sentinel-core
npm install
```

Create a `.env` file in the root directory:

```env
VITE_SUPABASE_URL=your_supabase_project_url
VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
```

Start the development server:

```bash
npm run dev
```

Visit `http://localhost:5173`

## 📡 Supabase Real-Time API

Sentinel-Core relies on Supabase Realtime instead of traditional REST endpoints.

  - **Channel**: `soc-realtime`
  - **Events Listened**:
      - `*` (INSERT, UPDATE, DELETE) on `public.alerts`
      - `INSERT` on `public.logs`
  - **Action Strategy**: All UI buttons dispatch `UPDATE` requests directly to PostgreSQL, which broadcasts the change back to all connected clients instantly.

## ☁️ Production Deployment

### Option A: Vercel (Recommended)

1.  Push your repository to GitHub.
2.  Import the project in Vercel.
3.  Add `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` to Vercel's Environment Variables.
4.  Deploy.

### Option B: Hugging Face Spaces (Static)

1.  Run `npm run build` locally.
2.  Create a new Hugging Face Space (Select SDK: **Static**).
3.  Upload the contents of your `dist/` folder directly to the Hugging Face files tab.

## 🎮 How to Use

1.  **Login** with the credentials you created in Supabase Auth.
2.  **Review Alerts** in the left panel of the Operations Center.
3.  **Select an alert** from the table.
4.  **Take action**:
      - `Investigate` → Analyst review sequence.
      - `Block IP` → Stops attacker (best for high severity).
      - `Isolate Host` → Contains compromise (resets host risk).
      - `Ignore` → Dismiss (Penalty if high severity\!).
      - `Resolve` → Close the incident.
5.  **Enable Auto-play** to watch the AI agent take over the SOC, injecting and resolving threats.
6.  **Switch to Analytics** to view the live charts react to the ongoing attacks.

## 🧠 Simulation Details

The Sentinel-Core engine simulates:

  - **12 cloud hosts** with dynamic, fluctuating risk scores calculated per-second.
  - **7 realistic alert types**: PortScan, BruteForce, Phishing, Suspicious PowerShell, Lateral Movement, IAM Privilege Escalation, Ransomware.
  - **Host compromise logic**: A host turns RED if targeted by a High-severity attack or if its aggregate risk score exceeds 85%.
  - **Environmental drift**: The `runAgentStep` loop ensures constant background noise and activity.

## 🛠️ Tech Stack

**Frontend:**

  - React 18 with TypeScript
  - Vite
  - Tailwind CSS
  - Recharts for live visualization

**Backend & Data Layer:**

  - Supabase Authentication
  - PostgreSQL
  - Supabase Client (`@supabase/supabase-js`)

## 📁 Project Structure

```text
sentinel-core/
├── src/
│   ├── App.tsx               # Main application (Auth, Ops, Analytics)
│   ├── supabaseClient.ts     # Database connection config
│   ├── main.tsx              # React DOM entry
│   └── index.css             # Tailwind imports
├── public/
├── index.html
├── package.json
├── vite.config.ts
└── .env                      # API Keys (Do not commit)
```

## 🔒 Security Notes

This is a **simulation dashboard**:

  - **Environment Variables**: Never commit your `.env` file to GitHub.
  - **RLS**: Row Level Security is currently disabled for ease of demoing. In a true production environment, enable RLS and strictly define read/write policies based on `auth.uid()`.
  - **Authentication**: JWT secrets are managed natively by Supabase.

## 🎨 UI Highlights

  - Dark SOC theme (`#030508` background).
  - Glassmorphism input cards with subtle backdrop blurs.
  - Animated gradient orbs for login focus.
  - Real-time drawing Recharts with customized tooltips.
  - Status and Severity Pills with explicit alpha-channel borders.
  - Custom handcrafted SVG iconography.

## 📊 Metrics Explained

  - **Score**: Overall SOC health (0-100%). Drops based on active threats and compromised hosts.
  - **Anomaly Score**: Algorithmically generated metric indicating unusual network activity.
  - **CPU Usage**: Simulated cluster-wide compute drain from malware/mining operations.
  - **Compromised Hosts**: Number of instances requiring immediate isolation.
  - **Confidence**: Threat Intelligence certainty (60-99%).

## 🤝 Contributing

This is a portfolio and demonstration project. To extend:

1.  Connect to an actual SIEM (Splunk, Microsoft Sentinel) via webhooks to feed real alerts to the Supabase database.
2.  Expand the `runAgentStep` logic to include complex, multi-stage attack playbooks.
3.  Add Multi-tenant support with organizations in Supabase.

## 📄 License

MIT - Free to use, modify, and distribute for education and demos.

-----

**Built for cybersecurity training, SOC simulation, and cloud-native monitoring.**
