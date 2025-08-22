# AppBlocker

## Overview

AppBlocker is a Windows desktop application built with Electron.js designed to block access to all websites and applications except those explicitly whitelisted by the user. It modifies the Windows hosts file to block websites and monitors running processes to terminate unauthorized applications. The app also supports blocking the Windows File Explorer as a toggle. Access and disabling require a password set on first run. A global hotkey (Ctrl+Shift+Alt+Q) brings up the password prompt to disable blocking.

## Features

- First run password setup with secure bcrypt hashing.
- Hosts file manipulation to block all websites except whitelisted domains.
- Process monitoring to terminate non-whitelisted applications.
- Toggle blocking of Windows File Explorer (explorer.exe).
- Global hotkey to open password prompt (Ctrl+Shift+Alt+Q).
- Whitelist management UI for websites and applications.
- Logs all blocked attempts, process kills, and user actions.
- Cannot be disabled or closed without password.

## Requirements

- Windows 10 or later
- Node.js (version 18 or later recommended)
- Administrative privileges to modify hosts file and terminate processes

## Setup Instructions

1. **Install Node.js**

Download and install Node.js from [https://nodejs.org/](https://nodejs.org/). Choose the latest LTS version recommended for most users.

2. **Clone or Download AppBlocker**

Download the project files to a folder on your Windows machine.

3. **Install Dependencies**

Open a PowerShell or Command Prompt window in the project folder and run:

