# Password Manager

A secure, offline-first, client-side Password Manager inspired by KeeWeb with Material You design and local JSON vault support. Built using pure vanilla HTML5, CSS3, and ES6+ TypeScript.

## Main Features

- **Material You UI/UX Theme**: Professional, high-contrast, dual light/dark aesthetics with round corners, gentle transitions, and generous layout spacing.
- **Full Offline Operations**: All vaults stay in your control. Create, edit, and save directly to your own `.json` database file.
- **Group Management**: Organise credentials in tree-structured directories.
- **Time-Based One-Time Passwords (TOTP)**: Custom integrated Base32 decoder and SHA1-HMAC algorithm calculates and copies TOTP pin codes on a 30-second loop.
- **Robust Password Generator**: Direct options for password complexity and safety checks.
- **Multilingual Localization**: Native support for English, Tiếng Việt, Español, and Français with external fallback fail-safes.

## Technical Execution

The workspace uses Vite to bundle the static source. The core system runs in `/src/app.ts`, utilizing classical vanilla DOM queries:

- `/public/translations/`: Localized dictionary objects (`en.json`, `vi.json`, `es.json`, `fr.json`).
- `/public/sample.json`: Fully hydrated prepopulated dataset for standard onboarding runs.
- `/src/index.css`: Universal Tailwind styles + Material You CSS variables config.
- `/src/app.ts`: Unified manager instance (I18n, Hot Clipboard, Password Gen, Vault Engine, TOTP Counter) in pure vanilla TypeScript.

## How to Run

1. Run standard development server:
   ```bash
   npm run dev
   ```
2. Build for distribution/deployment (builds compilation in `/dist`):
   ```bash
   npm run build
   ```
