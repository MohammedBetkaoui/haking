const { app, BrowserWindow, ipcMain, screen } = require('electron');
const path = require('path');
const http = require('http');
const fs = require('fs');

let mainWindow = null;
let isExpanded = false;
let collapsedPosition = null;
let positionFilePath = null;
let persistPositionTimeout = null;
const isDev = !app.isPackaged;
const DEV_URL = 'http://localhost:5173';

const BTN_SIZE = 64;
const PANEL_W  = 380;
const PANEL_H  = 520;
const WINDOW_MARGIN = 16;
const POSITION_FILE = 'guardian-button-position.json';
const POSITION_SAVE_DEBOUNCE_MS = 180;

function getPositionFilePath() {
  if (!positionFilePath) {
    positionFilePath = path.join(app.getPath('userData'), POSITION_FILE);
  }
  return positionFilePath;
}

function normalizePosition(value) {
  if (!value || !Number.isFinite(value.x) || !Number.isFinite(value.y)) return null;
  return { x: Math.round(value.x), y: Math.round(value.y) };
}

function loadCollapsedPosition() {
  try {
    const raw = fs.readFileSync(getPositionFilePath(), 'utf8');
    const parsed = JSON.parse(raw);
    return normalizePosition(parsed);
  } catch (_error) {
    return null;
  }
}

function persistCollapsedPositionImmediate() {
  if (!app.isReady() || !collapsedPosition) return;

  const normalized = normalizePosition(collapsedPosition);
  if (!normalized) return;

  try {
    const targetFile = getPositionFilePath();
    fs.mkdirSync(path.dirname(targetFile), { recursive: true });
    fs.writeFileSync(targetFile, JSON.stringify(normalized), 'utf8');
  } catch (_error) {
    // Ignore persistence failures to avoid breaking app interactions.
  }
}

function schedulePersistCollapsedPosition() {
  if (!app.isReady() || !collapsedPosition) return;

  if (persistPositionTimeout) {
    clearTimeout(persistPositionTimeout);
  }

  persistPositionTimeout = setTimeout(() => {
    persistPositionTimeout = null;
    persistCollapsedPositionImmediate();
  }, POSITION_SAVE_DEBOUNCE_MS);
}

function flushCollapsedPositionPersistence() {
  if (persistPositionTimeout) {
    clearTimeout(persistPositionTimeout);
    persistPositionTimeout = null;
  }
  persistCollapsedPositionImmediate();
}

function updateCollapsedPosition(nextPosition) {
  const normalized = normalizePosition(nextPosition);
  if (!normalized) return;
  collapsedPosition = normalized;
  schedulePersistCollapsedPosition();
}

function clampToWorkArea(x, y, width, height, workArea) {
  const maxX = workArea.x + workArea.width - width;
  const maxY = workArea.y + workArea.height - height;

  return {
    x: Math.round(Math.min(Math.max(x, workArea.x), maxX)),
    y: Math.round(Math.min(Math.max(y, workArea.y), maxY)),
  };
}

function getWorkAreaForPoint(x, y) {
  return screen.getDisplayNearestPoint({ x: Math.round(x), y: Math.round(y) }).workArea;
}

function getWorkAreaForWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    return screen.getDisplayMatching(mainWindow.getBounds()).workArea;
  }
  return screen.getPrimaryDisplay().workArea;
}

function getAnchoredBounds(width, height, workArea = getWorkAreaForWindow()) {
  const safeWidth = Math.min(width, workArea.width);
  const safeHeight = Math.min(height, workArea.height);
  const pos = clampToWorkArea(
    workArea.x + workArea.width - safeWidth - WINDOW_MARGIN,
    workArea.y + workArea.height - safeHeight - WINDOW_MARGIN,
    safeWidth,
    safeHeight,
    workArea,
  );

  return {
    width: safeWidth,
    height: safeHeight,
    x: pos.x,
    y: pos.y,
  };
}

function getCollapsedBounds() {
  if (!collapsedPosition) {
    const anchored = getAnchoredBounds(BTN_SIZE, BTN_SIZE);
    updateCollapsedPosition({ x: anchored.x, y: anchored.y });
    return anchored;
  }

  const workArea = getWorkAreaForPoint(collapsedPosition.x, collapsedPosition.y);
  const width = Math.min(BTN_SIZE, workArea.width);
  const height = Math.min(BTN_SIZE, workArea.height);
  const clamped = clampToWorkArea(
    collapsedPosition.x,
    collapsedPosition.y,
    width,
    height,
    workArea,
  );

  updateCollapsedPosition(clamped);
  return { width, height, x: clamped.x, y: clamped.y };
}

function getExpandedBoundsFromCollapsed() {
  const collapsed = getCollapsedBounds();
  const workArea = getWorkAreaForPoint(collapsed.x, collapsed.y);

  const width = Math.min(PANEL_W, workArea.width);
  const height = Math.min(PANEL_H, workArea.height);

  const preferredX = collapsed.x - (width - collapsed.width);
  const preferredY = collapsed.y - (height - collapsed.height);
  const clamped = clampToWorkArea(preferredX, preferredY, width, height, workArea);

  // Keep the collapsed slot aligned with the button's bottom-right corner after clamping.
  updateCollapsedPosition({
    x: clamped.x + width - collapsed.width,
    y: clamped.y + height - collapsed.height,
  });

  return { width, height, x: clamped.x, y: clamped.y };
}

function setWindowMode(expanded, { focus = false } = {}) {
  if (!mainWindow || mainWindow.isDestroyed()) return;

  const target = expanded
    ? getExpandedBoundsFromCollapsed()
    : getCollapsedBounds();

  mainWindow.setBounds(target);
  isExpanded = expanded;

  if (focus) {
    mainWindow.setFocusable(true);
    mainWindow.focus();
  }
}

function waitForDevServer(url, retries = 40, delayMs = 500) {
  return new Promise((resolve) => {
    function attempt(remaining) {
      http.get(url, (res) => { res.resume(); resolve(); })
        .on('error', () => {
          if (remaining <= 0) { resolve(); return; }
          setTimeout(() => attempt(remaining - 1), delayMs);
        });
    }
    attempt(retries);
  });
}

async function createWindow() {
  const initialBounds = getCollapsedBounds();

  mainWindow = new BrowserWindow({
    width: initialBounds.width,
    height: initialBounds.height,
    x: initialBounds.x,
    y: initialBounds.y,
    frame: false,
    transparent: true,
    alwaysOnTop: true,
    skipTaskbar: true,
    resizable: false,
    hasShadow: false,
    focusable: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });

  if (isDev) {
    await waitForDevServer(DEV_URL);
    mainWindow.loadURL(DEV_URL);
  } else {
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  }

  mainWindow.webContents.on('did-fail-load', (_e, code, _d, url) => {
    if (code === -3) return;
    setTimeout(() => {
      if (!mainWindow || mainWindow.isDestroyed()) return;
      isDev ? mainWindow.loadURL(DEV_URL) : mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
    }, 1000);
  });

  mainWindow.setVisibleOnAllWorkspaces(true, { visibleOnFullScreen: true });
}

ipcMain.on('bar:move', (_event, payload = {}) => {
  if (!mainWindow || mainWindow.isDestroyed() || isExpanded) return;

  const { screenX, screenY, offsetX, offsetY } = payload;
  if (
    !Number.isFinite(screenX)
    || !Number.isFinite(screenY)
    || !Number.isFinite(offsetX)
    || !Number.isFinite(offsetY)
  ) {
    return;
  }

  const bounds = mainWindow.getBounds();
  const workArea = getWorkAreaForPoint(screenX, screenY);
  const preferredX = screenX - offsetX;
  const preferredY = screenY - offsetY;
  const clamped = clampToWorkArea(preferredX, preferredY, bounds.width, bounds.height, workArea);

  updateCollapsedPosition(clamped);
  mainWindow.setPosition(clamped.x, clamped.y);
});

// ---- IPC: expand — grow to panel, anchored bottom-right ----
ipcMain.on('bar:expand', () => {
  setWindowMode(true, { focus: true });
});

// ---- IPC: collapse — back to button, bottom-right ----
ipcMain.on('bar:collapse', () => {
  setWindowMode(false);
});

// ---- IPC: system info ----
ipcMain.removeHandler('system:info');
ipcMain.handle('system:info', () => {
  const os = require('os');
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    release: os.release(),
    username: os.userInfo().username,
  };
});

app.whenReady().then(async () => {
  collapsedPosition = loadCollapsedPosition();
  await createWindow();

  const reanchorWindow = () => {
    setWindowMode(isExpanded);
  };

  screen.on('display-metrics-changed', reanchorWindow);
  screen.on('display-added', reanchorWindow);
  screen.on('display-removed', reanchorWindow);

  app.on('activate', async () => {
    if (BrowserWindow.getAllWindows().length === 0) await createWindow();
  });
});

app.on('before-quit', () => {
  flushCollapsedPositionPersistence();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
