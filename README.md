# 🔐 Professional Offline-First Password & Credentials Manager

An elegant, secure, and 100% offline-first client-side credentials manager inspired by KeeWeb. Features standard dual-pane information architecture, Time-Based One-Time Passwords (TOTP) generation, and active Material You / Material 3 dynamic color customization.

Built cleanly on raw vanilla Web Technologies (**HTML5**, **Tailwind CSS v4**, and **TypeScript**) for ultra-fast load times, lightweight bundle footprint, and maximum interoperability.

---

## ✨ Key Capabilities

### 📱 1. Distinctive UI & Material You Theme Design
- **Adaptive Accent Color Palette**: Dynamically extract vibrant hues from uploaded wallpapers or enter hex values, generating full high-contrast, accessible Material 3 dynamic color rules on the fly.
- **Strict Accessibility (A11y)**: Built-in standard, medium, and high contrast scaling modes strictly complying with WCAG contrast ratios.
- **Smooth Transition Ergonomics**: Zero-jank spatial layout shifts, staggered entry list lists, micro-hover animations, and fluid responsive toggles for mobile viewports.

### 🛡️ 2. Absolute Data Self-Custody
- **Offline Integrity**: Zero network server connections are forced. Your usernames, passwords, notes, and secrets stay purely in your own environment.
- **Flexible JSON Vault Mechanics**: Native capabilities to create new vaults, open exists, or export current databases instantly. Supports both plaintext JSON structures and AES-GCM 256-bit encrypted master password database configurations.
- **Import Merger Utility**: Effortlessly merge separate ledger configurations with collision avoidance. Duplicate titles are handled gracefully during upload.

### 🔑 3. Integrated Security Tooling
- **Time-Based One-Time Passwords (TOTP)**: Built-in native Base32 key decoder and HMAC-SHA1 cryptographic loop. Live countdown loaders recalculate and copy your rotating 2FA authorization codes on standard 30-second intervals.
- **Advanced Password Constructor**: Configurable criteria including length, uppercase, digits, symbols, and readable phonetic groupings. Live entropy/strength rating bar provides visual feedback.
- **Hot Clipboard Manager**: Copy secrets with a single button. Automatic local safe-timers clear your clipboard data after 15 seconds to prevent memory snooping.

### 🌐 4. Comprehensive Localization (i18n)
Full in-app support is baked in for:
- 🇺🇸 English (Default)
- 🇻🇳 Tiếng Việt
- 🇪🇸 Español
- 🇫🇷 Français

---

## 🏗️ Technical Architecture & Under-the-Hood Details

### 1. Data Structure Definitions
Vault data is defined in `src/types.ts` using highly structured TypeScript interfaces to guarantee type safety across the runtime:
```typescript
interface VaultData {
  vaultName: string;
  lastModified: string;
  groups: Group[];
  entries: Entry[];
}

interface Group {
  id: string;
  name: string;
  icon: string; // Lucide icon identifier
}

interface Entry {
  id: string;
  groupId: string; // Links entry to custom group
  title: string;
  username: string;
  password?: string;
  url: string;
  notes: string;
  totpSecret?: string; // Standard Base32 string
  tags: string[];
  modified: string;
}
```

### 2. Time-Based One-Time Password Engine (TOTP)
TOTP requires converting a Base32 string parameter into binary bytes, calculating the hash on current Unix block times ($T = \lfloor \text{currentTime} / 30 \rfloor$), and doing dynamic truncation:
1. **Base-32 Decoding**:
   Transforms standard Base32 encoded secrets into standard Uint8Array vectors.
2. **HMAC-SHA1 Execution**:
   Utilizes low-level cryptographic functions to sign the 8-byte message block ($T$).
3. **Dynamic Truncation**:
   Extracts a 4-byte subset from the signed digest using the last byte's lower 4 bits as an offset, then performs modulo $10^6$ to output a beautiful 6-digit pin.

### 3. Clipboard Protection Daemon
To prevent unauthorized shoulder-surfing, any clicked "Copy" button sets an active timer thread. After exactly 15 seconds, a secure overwrite wipe executes if the copied secret matches the clipboard state.

---

## 📂 Codebase Organization

The project adopts a structured, easily navigable file tree:
- **`index.html`**: The unified, beautifully responsive master viewport container containing skeleton sidebars, scroll panes, and accessible modal views.
- **`src/main.ts`**: Launches the main application instance on startup.
- **`src/index.css`**: Mounts Tailwind CSS v4 directives alongside comprehensive `:root` and `:root.dark` custom Material You properties. Includes custom utilities for range sliders, scrolls, and animation frames.
- **`src/app.ts`**: The core conductor of the application managing state, drawing, i18n translation switches, clipboard protection thresholds, local dynamic palette engines, and keyboard shortcuts.
- **`public/translations/`**: External dictionary catalog profiles supporting multilingual fail-safes.

---

## 🚀 Setting Up the Application

Ensure you have **Node.js** (v18+) and your package manager configured.

### 1. Installation
Install all dependency requirements defined in `package.json`:
```bash
npm install
```

### 2. Run Locally in Development
Boot a high-perf Vite local dev server to preview changes instantly:
```bash
npm run dev
```

---

## 🎨 Theme Customization Guides

The app supports custom Material You extraction. Navigate to **Settings (Gear Icon) -> Theme** select options:
1. **Choose Present**: Select from precompiled harmonious pairs (Teal, Blue, Ruby, Amber).
2. **Pick Custom Color**: Input precise HEX strings or click the native color picker wheel.
3. **From Wallpaper**: Drag and drop your favorite cover photo. The built-in extraction algorithm gathers the dominant color palettes, computes standard saturation ranges, and re-themes the workspace immediately.
