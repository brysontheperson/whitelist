const { app, BrowserWindow, ipcMain, globalShortcut, dialog } = require('electron');
const fs = require('fs/promises');
const fsSync = require('fs');
const path = require('path');
const os = require('os');
const child_process = require('child_process');
const bcrypt = require('bcryptjs');
const { machineIdSync } = require('node-machine-id');
require('dotenv').config();

const HOSTS_FILE_PATH = process.env.HOSTS_FILE_PATH || 'C:\\Windows\\System32\\drivers\\etc\\hosts';
const LOG_FILE_PATH = process.env.LOG_FILE_PATH || 'C:\\ProgramData\\AppBlocker\\appblocker.log';
const FILES_APP_PROCESS_NAME = process.env.FILES_APP_PROCESS_NAME || 'explorer.exe';
const PASSWORD_HASH_SALT_ROUNDS = parseInt(process.env.PASSWORD_HASH_SALT_ROUNDS, 10) || 10;

const APP_DATA_PATH = path.join(app.getPath('userData'));
const MODELS_PATH = path.join(APP_DATA_PATH, 'models');
const LOGS_PATH = path.join(APP_DATA_PATH, 'logs');
const WHITELIST_FILE = path.join(MODELS_PATH, 'whitelist.json');
const PASSWORD_FILE = path.join(MODELS_PATH, 'password.json');
const LOG_FILE = LOG_FILE_PATH || path.join(LOGS_PATH, 'log.txt');

// Ensure necessary directories exist
(async () => {
  try {
    await fs.mkdir(MODELS_PATH, { recursive: true });
    await fs.mkdir(LOGS_PATH, { recursive: true });
  } catch (e) {
    console.error('Error creating app data directories', e);
  }
})();

let mainWindow = null;
let passwordWindow = null;
let isBlockingEnabled = true;
let whitelist = {
  websites: [],
  applications: []
};
let blockFilesApp = false;
let hostsFileOriginalContent = '';
let hostsFileBlockedContent = '';
let processMonitorInterval = null;

function logEvent(message) {
  const timestamp = new Date().toISOString();
  const logLine = `[${timestamp}] ${message}\n`;
  fs.appendFile(LOG_FILE, logLine).catch(() => {
    // Fail silently
  });
}

// Read whitelist from file or create default
async function loadWhitelist() {
  try {
    const data = await fs.readFile(WHITELIST_FILE, 'utf-8');
    whitelist = JSON.parse(data);
    if (!Array.isArray(whitelist.websites)) whitelist.websites = [];
    if (!Array.isArray(whitelist.applications)) whitelist.applications = [];
  } catch {
    whitelist = { websites: [], applications: [] };
    await saveWhitelist();
  }
}

// Save whitelist to file
async function saveWhitelist() {
  try {
    await fs.writeFile(WHITELIST_FILE, JSON.stringify(whitelist, null, 2));
  } catch (e) {
    logEvent(`Error saving whitelist: ${e.message}`);
  }
}

// Read password hash from file
async function loadPasswordHash() {
  try {
    const data = await fs.readFile(PASSWORD_FILE, 'utf-8');
    const json = JSON.parse(data);
    if (json.hash && typeof json.saltRounds === 'number') {
      return json;
    }
    return null;
  } catch {
    return null;
  }
}

// Save password hash to file
async function savePasswordHash(hash, saltRounds) {
  try {
    await fs.writeFile(PASSWORD_FILE, JSON.stringify({ hash, saltRounds }, null, 2));
  } catch (e) {
    logEvent(`Error saving password hash: ${e.message}`);
  }
}

// Check if first run (no password file)
async function isFirstRun() {
  try {
    await fs.access(PASSWORD_FILE);
    return false;
  } catch {
    return true;
  }
}

// Create main application window
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      enableRemoteModule: false,
    },
    resizable: false,
    title: 'AppBlocker - Whitelist Management',
  });

  mainWindow.on('close', (e) => {
    if (isBlockingEnabled) {
      e.preventDefault();
      dialog.showMessageBox(mainWindow, {
        type: 'warning',
        title: 'AppBlocker',
        message: 'You must disable blocking before closing the application.',
      });
    }
  });

  mainWindow.loadFile(path.join(__dirname, 'ui', 'main.html'));
}

// Create login window for password prompt or setup
function createLoginWindow() {
  mainWindow = new BrowserWindow({
    width: 400,
    height: 350,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      enableRemoteModule: false,
    },
    resizable: false,
    title: 'AppBlocker - Login',
  });

  mainWindow.loadFile(path.join(__dirname, 'ui', 'index.html'));
}

// Create password prompt window for global hotkey
function createPasswordPromptWindow() {
  if (passwordWindow) {
    passwordWindow.focus();
    return;
  }

  passwordWindow = new BrowserWindow({
    width: 400,
    height: 250,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      enableRemoteModule: false,
    },
    resizable: false,
    title: 'AppBlocker - Enter Password',
    parent: mainWindow,
    modal: true,
  });

  passwordWindow.loadFile(path.join(__dirname, 'ui', 'index.html'));

  passwordWindow.on('closed', () => {
    passwordWindow = null;
  });
}

// Hosts file backup and restore helpers
async function backupHostsFile() {
  try {
    if (!fsSync.existsSync(HOSTS_FILE_PATH)) return;
    const backupPath = HOSTS_FILE_PATH + '.appblocker.bak';
    await fs.copyFile(HOSTS_FILE_PATH, backupPath);
  } catch (e) {
    logEvent(`Error backing up hosts file: ${e.message}`);
  }
}

async function restoreHostsFile() {
  try {
    const backupPath = HOSTS_FILE_PATH + '.appblocker.bak';
    if (fsSync.existsSync(backupPath)) {
      await fs.copyFile(backupPath, HOSTS_FILE_PATH);
      await fs.unlink(backupPath);
      logEvent('Hosts file restored from backup.');
    }
  } catch (e) {
    logEvent(`Error restoring hosts file: ${e.message}`);
  }
}

// Generate hosts entries to block all except whitelisted websites
function generateBlockedHostsEntries(whitelistWebsites) {
  // Block all by redirecting wildcard domains to 127.0.0.1 except whitelist.
  // Since hosts file does not support wildcard, implement blocking by blocking known domains or large known domains.
  // To block all except whitelist, we will:
  //  - Block localhost for all except whitelist by adding entries for all top-level domains? Not feasible.
  //  - Instead, we will block known large domains but for this app, we block common domains except whitelist.
  // Because hosts file cannot block wildcard fully, the typical approach is to add entries for big domains.
  // Here, to simulate blocking all non-whitelisted, we block common domains except whitelist.
  // So, we will block a big list of common domains except whitelist.

  // For demonstration, block commonly accessed domains except whitelist.
  // Real implementation should periodically update large domain list.
  // Here we use a small representative list for demonstration.

  const commonDomainsToBlock = [
    'google.com', 'facebook.com', 'youtube.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'wikipedia.org', 'reddit.com', 'netflix.com', 'amazon.com',
    'bing.com', 'microsoft.com', 'apple.com', 'office.com', 'zoom.us',
  ];

  // Filter out whitelisted domains from block list
  const toBlock = commonDomainsToBlock.filter(d => !whitelistWebsites.includes(d.toLowerCase()));

  let entries = '';
  for (const domain of toBlock) {
    entries += `127.0.0.1    ${domain}\n`;
    entries += `127.0.0.1    www.${domain}\n`;
  }
  return entries;
}

// Apply hosts file blocking
async function applyHostsBlocking() {
  try {
    const originalContent = await fs.readFile(HOSTS_FILE_PATH, 'utf-8');
    hostsFileOriginalContent = originalContent;

    // Remove previous appblocker entries if any
    const markerStart = '# AppBlocker Start';
    const markerEnd = '# AppBlocker End';

    let contentWithoutBlock = originalContent;
    const startIndex = originalContent.indexOf(markerStart);
    const endIndex = originalContent.indexOf(markerEnd);

    if (startIndex !== -1 && endIndex !== -1 && endIndex > startIndex) {
      contentWithoutBlock = originalContent.slice(0, startIndex) + originalContent.slice(endIndex + markerEnd.length);
    }

    const blockEntries = generateBlockedHostsEntries(whitelist.websites);

    hostsFileBlockedContent =
      contentWithoutBlock.trim() +
      `\n${markerStart}\n${blockEntries}${markerEnd}\n`;

    await backupHostsFile();
    await fs.writeFile(HOSTS_FILE_PATH, hostsFileBlockedContent, { encoding: 'utf-8' });
    logEvent('Hosts file blocking applied.');
  } catch (e) {
    logEvent(`Error applying hosts blocking: ${e.message}`);
  }
}

// Remove hosts file blocking entries
async function removeHostsBlocking() {
  try {
    if (!hostsFileOriginalContent) {
      await restoreHostsFile();
      return;
    }
    await fs.writeFile(HOSTS_FILE_PATH, hostsFileOriginalContent, 'utf-8');
    logEvent('Hosts file blocking removed.');
  } catch (e) {
    logEvent(`Error removing hosts blocking: ${e.message}`);
  }
}

// Get list of running processes (returns array of process executable names)
function getRunningProcesses() {
  return new Promise((resolve) => {
    // Use tasklist command to get process list
    child_process.exec('tasklist /FO CSV /NH', (error, stdout) => {
      if (error) {
        resolve([]);
        return;
      }
      // Parse CSV output: "Image Name","PID","Session Name","Session#","Mem Usage"
      const lines = stdout.trim().split('\n');
      const processes = lines.map(line => {
        const cols = line.split('","').map(s => s.replace(/^"|"$/g, ''));
        return cols[0].toLowerCase();
      });
      resolve(processes);
    });
  });
}

// Terminate a process by executable name
function terminateProcessByName(processName) {
  return new Promise((resolve) => {
    // Use taskkill command
    child_process.exec(`taskkill /IM "${processName}" /F`, (error) => {
      // Ignore errors (process might not exist)
      resolve(!error);
    });
  });
}

// Check processes and terminate non-whitelisted
async function monitorProcesses() {
  if (!isBlockingEnabled) return;

  try {
    const runningProcesses = await getRunningProcesses();
    for (const proc of runningProcesses) {
      if (proc === 'tasklist.exe' || proc === 'taskkill.exe' || proc === 'cmd.exe' || proc === 'powershell.exe') {
        // always allow system tools
        continue;
      }
      if (blockFilesApp && proc === FILES_APP_PROCESS_NAME.toLowerCase()) {
        await terminateProcessByName(proc);
        logEvent(`Terminated blocked process: ${proc}`);
        continue;
      }
      if (!whitelist.applications.map(a => a.toLowerCase()).includes(proc)) {
        if (proc !== FILES_APP_PROCESS_NAME.toLowerCase()) {
          await terminateProcessByName(proc);
          logEvent(`Terminated blocked process: ${proc}`);
        }
      }
    }
  } catch (e) {
    logEvent(`Error monitoring processes: ${e.message}`);
  }
}

// Start process monitor interval
function startProcessMonitor() {
  if (processMonitorInterval) clearInterval(processMonitorInterval);
  processMonitorInterval = setInterval(monitorProcesses, 5000);
}

// Stop process monitor
function stopProcessMonitor() {
  if (processMonitorInterval) {
    clearInterval(processMonitorInterval);
    processMonitorInterval = null;
  }
}

// Enable blocking: hosts blocking + process monitoring
async function enableBlocking() {
  isBlockingEnabled = true;
  await applyHostsBlocking();
  startProcessMonitor();
  logEvent('Blocking enabled.');
  if (mainWindow) {
    mainWindow.webContents.send('blocking-status-changed', isBlockingEnabled);
  }
}

// Disable blocking: restore hosts, stop process monitor
async function disableBlocking() {
  isBlockingEnabled = false;
  await removeHostsBlocking();
  stopProcessMonitor();
  logEvent('Blocking disabled.');
  if (mainWindow) {
    mainWindow.webContents.send('blocking-status-changed', isBlockingEnabled);
  }
}

// Handle IPC messages from renderer

ipcMain.handle('password-set', async (event, password) => {
  try {
    const saltRounds = PASSWORD_HASH_SALT_ROUNDS;
    const hash = await bcrypt.hash(password, saltRounds);
    await savePasswordHash(hash, saltRounds);
    logEvent('Password set by user.');
    return { success: true };
  } catch (e) {
    return { success: false, message: e.message };
  }
});

ipcMain.handle('password-verify', async (event, password) => {
  try {
    const passwordData = await loadPasswordHash();
    if (!passwordData) return { success: false, message: 'Password not set.' };
    const match = await bcrypt.compare(password, passwordData.hash);
    if (match) {
      logEvent('Password verified successfully.');
      return { success: true };
    } else {
      logEvent('Password verification failed.');
      return { success: false, message: 'Incorrect password.' };
    }
  } catch (e) {
    return { success: false, message: e.message };
  }
});

ipcMain.handle('whitelist-get', async () => {
  await loadWhitelist();
  return whitelist;
});

ipcMain.handle('whitelist-update', async (event, updatedWhitelist) => {
  if (!updatedWhitelist || typeof updatedWhitelist !== 'object') {
    return { success: false, message: 'Invalid whitelist data.' };
  }
  whitelist.websites = Array.isArray(updatedWhitelist.websites) ? updatedWhitelist.websites : [];
  whitelist.applications = Array.isArray(updatedWhitelist.applications) ? updatedWhitelist.applications : [];
  await saveWhitelist();
  await applyHostsBlocking();
  logEvent('Whitelist updated by user.');
  return { success: true };
});

ipcMain.handle('toggle-block-files-app', async (event, toggleState) => {
  blockFilesApp = toggleState === true;
  logEvent(`Files app blocking toggled: ${blockFilesApp}`);
  return { success: true };
});

ipcMain.handle('blocking-status-request', async () => {
  return isBlockingEnabled;
});

ipcMain.handle('password-change', async (event, currentPassword, newPassword) => {
  try {
    const passwordData = await loadPasswordHash();
    if (!passwordData) return { success: false, message: 'Current password not set.' };
    const match = await bcrypt.compare(currentPassword, passwordData.hash);
    if (!match) return { success: false, message: 'Current password incorrect.' };
    const saltRounds = PASSWORD_HASH_SALT_ROUNDS;
    const newHash = await bcrypt.hash(newPassword, saltRounds);
    await savePasswordHash(newHash, saltRounds);
    logEvent('Password changed by user.');
    return { success: true };
  } catch (e) {
    return { success: false, message: e.message };
  }
});

ipcMain.handle('request-logs', async () => {
  try {
    const data = await fs.readFile(LOG_FILE, 'utf-8');
    return { success: true, logs: data };
  } catch {
    return { success: false, logs: '' };
  }
});

// Handle app ready
app.whenReady().then(async () => {
  await loadWhitelist();

  const firstRun = await isFirstRun();

  if (firstRun) {
    createLoginWindow();
  } else {
    createLoginWindow();
  }

  registerGlobalHotkey();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      if (isBlockingEnabled) {
        createMainWindow();
      } else {
        createLoginWindow();
      }
    }
  });
});

// Register global hotkey Ctrl+Shift+Alt+Q
function registerGlobalHotkey() {
  const ret = globalShortcut.register('Control+Shift+Alt+Q', () => {
    if (!passwordWindow) {
      createPasswordPromptWindow();
    } else {
      passwordWindow.focus();
    }
  });

  if (!ret) {
    logEvent('Global hotkey registration failed.');
  } else {
    logEvent('Global hotkey Ctrl+Shift+Alt+Q registered.');
  }
}

// Unregister global hotkeys on quit
app.on('will-quit', () => {
  globalShortcut.unregisterAll();
});

// IPC to handle successful login to show main window
ipcMain.on('login-success', async () => {
  if (mainWindow) {
    mainWindow.close();
    mainWindow = null;
  }
  createMainWindow();
  await enableBlocking();
});

// IPC to handle blocking disable request after password verification
ipcMain.on('disable-blocking', async () => {
  await disableBlocking();
});

// IPC to handle enable blocking request after password verification
ipcMain.on('enable-blocking', async () => {
  await enableBlocking();
});

// Quit app only if blocking disabled
app.on('before-quit', (e) => {
  if (isBlockingEnabled) {
    e.preventDefault();
    dialog.showMessageBox({
      type: 'warning',
      title: 'AppBlocker',
      message: 'Disable blocking before quitting the application.',
    });
  }
});
