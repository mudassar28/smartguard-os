# 🛡️ SmartGuard_OS v2.0

**Web3 Triage & Threat Intelligence Platform**

SmartGuard_OS is an automated smart contract auditing tool designed to provide rapid security triage, vulnerability detection, and remediation strategies for Web3 developers. Powered by advanced LLM analysis, it acts as a first line of defense against smart contract exploits.

## ✨ Features

* **Instant Security Triage:** Paste any Solidity smart contract and initiate a comprehensive scan in seconds.
* **Executive Summaries:** High-level risk overviews designed for non-technical stakeholders and CTOs.
* **Deep Vulnerability Analysis:** Granular breakdowns of detected issues, including severity, location, and impact.
* **Red Team Attack Simulation:** Step-by-step hypothetical attack paths demonstrating how a threat actor might exploit the contract.
* **Actionable Remediation:** Safe, patched code replacements provided directly within the dashboard.
* **PDF Report Generation:** Export full audit reports with one click for documentation and sharing.
* **Secure Architecture:** API keys and prompt logic are strictly isolated on the server-side via Next.js Server Actions to prevent exposure.

## 🛠️ Tech Stack

* **Frontend:** Next.js (App Router), React, Tailwind CSS
* **Backend:** Next.js Server Actions (Node.js environment)
* **AI Engine:** Google Gemini 2.5 Flash API
* **UI/UX:** Custom dark-mode terminal aesthetic with SVG data visualization

## 🚀 Getting Started

Follow these steps to run SmartGuard_OS locally on your machine.

### Prerequisites
* [Node.js](https://nodejs.org/) (v18 or higher recommended)
* [Git](https://git-scm.com/)

### Installation

1. **Clone the repository**
   ```bash
   git clone [https://github.com/mudassar28/smartguard-os.git](https://github.com/mudassar28/smartguard-os.git)
   cd smartguard-os
