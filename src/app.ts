/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import "./index.css";

// ==========================================
// PURE VANILLA PASSWORD MANAGER ENGINE (ES6+)
// ==========================================

// Global Interfaces
interface CustomField {
  name: string;
  value: string;
}

interface Group {
  id: string;
  name: string;
  icon: string;
}

interface Entry {
  id: string;
  groupId: string; // empty means General or no group
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  otpSecret: string;
  customFields: CustomField[];
  created: string;
  modified: string;
}

interface VaultData {
  vaultName: string;
  lastModified: string;
  groups: Group[];
  entries: Entry[];
}

// 1. DYNAMIC TRANSLATION SYSTEM
// Removed embedded dictionary for modular public/translations/*.json resource loading.

// 2. CRYPTO UTILITIES: BASE32 & HMAC-SHA1 ENGINE
function base32ToBytes(b32: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = b32.toUpperCase().replace(/[\s-]/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = alphabet.indexOf(cleaned[i]);
    if (idx === -1) continue; // ignore non-base32 or padding char '='
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}

function sha1(bytes: Uint8Array): Uint8Array {
  const l = bytes.length;
  const words = new Uint32Array(((l + 8) >> 6) + 1 << 4);
  for (let i = 0; i < l; i++) {
    const wordIndex = i >> 2;
    words[wordIndex] |= bytes[i] << (24 - (i & 3) * 8);
  }
  const endWordIndex = l >> 2;
  words[endWordIndex] |= 0x80 << (24 - (l & 3) * 8);
  words[words.length - 1] = l * 8;

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;

  const w = new Uint32Array(80);
  for (let i = 0; i < words.length; i += 16) {
    for (let t = 0; t < 16; t++) w[t] = words[i + t];
    for (let t = 16; t < 80; t++) {
      const val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
      w[t] = (val << 1) | (val >>> 31);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;

    for (let t = 0; t < 80; t++) {
      let f = 0;
      let k = 0;
      if (t < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5a827999;
      } else if (t < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (t < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[t]) | 0;
      e = d;
      d = c;
      c = (b << 30) | (b >>> 2);
      b = a;
      a = temp;
    }

    h0 = (h0 + a) | 0;
    h1 = (h1 + b) | 0;
    h2 = (h2 + c) | 0;
    h3 = (h3 + d) | 0;
    h4 = (h4 + e) | 0;
  }

  const result = new Uint8Array(20);
  for (let i = 0; i < 5; i++) {
    const h = [h0, h1, h2, h3, h4][i];
    result[i * 4] = (h >>> 24) & 0xff;
    result[i * 4 + 1] = (h >>> 16) & 0xff;
    result[i * 4 + 2] = (h >>> 8) & 0xff;
    result[i * 4 + 3] = h & 0xff;
  }
  return result;
}

function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
  const k = new Uint8Array(64);
  if (key.length > 64) {
    k.set(sha1(key));
  } else {
    k.set(key);
  }
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    ipad[i] = k[i] ^ 0x36;
    opad[i] = k[i] ^ 0x5c;
  }
  const tempMsg = new Uint8Array(64 + message.length);
  tempMsg.set(ipad);
  tempMsg.set(message, 64);
  const hash1 = sha1(tempMsg);

  const tempHash = new Uint8Array(64 + hash1.length);
  tempHash.set(opad);
  tempHash.set(hash1, 64);
  return sha1(tempHash);
}

function getTotp(secret: string, timeStep: number = 30): string {
  try {
    const key = base32ToBytes(secret);
    if (key.length === 0) return "000000";
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / timeStep);

    const msg = new Uint8Array(8);
    let tempCounter = counter;
    for (let i = 7; i >= 0; i--) {
      msg[i] = tempCounter & 0xff;
      tempCounter = Math.floor(tempCounter / 256);
    }

    const hmac = hmacSha1(key, msg);
    const offset = hmac[19] & 0xf;
    const code = ((hmac[offset] & 0x7f) << 24) |
                 ((hmac[offset + 1] & 0xff) << 16) |
                 ((hmac[offset + 2] & 0xff) << 8) |
                 (hmac[offset + 3] & 0xff);

    const totp = code % 1000000;
    return totp.toString().padStart(6, "0");
  } catch (e) {
    console.error("TOTP Computation Error:", e);
    return "000000";
  }
}

// 3. MASTER APPLICATION CONTROLLER
class AppManager {
  private vault: VaultData | null = null;
  private selectedEntryId: string | null = null;
  private selectedGroupId: string = "all"; // 'all' or actual ID
  private searchQuery: string = "";
  private sortingMode: "title" | "modified" = "title";
  private currentLanguage: string = "en";
  private theme: "light" | "dark" = "light";
  private loadedTranslations: Record<string, Record<string, string>> = {};

  // States
  private isEditingEntry: boolean = false;
  private editEntryState: Entry | null = null;

  constructor() {
    this.initLocale().then(() => {
      this.initTheme();
      this.bindEvents();
      this.loadHistory();
      this.hideInitSpinner();
      this.startTOTPTimer();
    });
  }

  // 4. LOCALE & TRANSLATIONS
  private async loadLanguage(lang: string) {
    if (this.loadedTranslations[lang]) return;
    try {
      const response = await fetch(`/translations/${lang}.json`);
      if (!response.ok) throw new Error(`HTTP status ${response.status}`);
      const data = await response.json();
      this.loadedTranslations[lang] = data;
    } catch (error) {
      console.error(`Failed to load translations for ${lang}:`, error);
      this.loadedTranslations[lang] = {};
    }
  }

  private async initLocale() {
    const savedLocale = localStorage.getItem("kw_password_manager_locale") || "en";
    await this.loadLanguage("en");
    if (savedLocale !== "en") {
      await this.loadLanguage(savedLocale);
    }
    await this.setLanguage(savedLocale);
  }

  private async setLanguage(lang: string) {
    this.currentLanguage = lang;
    localStorage.setItem("kw_password_manager_locale", lang);

    // Sync selectors
    const wSelect = document.getElementById("welcome-lang-select") as HTMLSelectElement;
    if (wSelect) wSelect.value = lang;
    const dSelect = document.getElementById("dashboard-lang-select") as HTMLSelectElement;
    if (dSelect) dSelect.value = lang;

    // Load actual translation file if not yet loaded
    await this.loadLanguage(lang);

    // Apply translations
    this.applyTranslations();
  }

  private applyTranslations() {
    const dict = this.loadedTranslations[this.currentLanguage] || this.loadedTranslations["en"] || {};

    // Update simple text items
    const translateLabel = (id: string, key: string) => {
      const el = document.getElementById(id);
      if (el) el.textContent = dict[key] || el.textContent;
    };

    translateLabel("lbl-welcome-title", "welcome_title");
    translateLabel("lbl-welcome-desc", "welcome_desc");
    translateLabel("lbl-create-new-vault", "create_new_vault");
    translateLabel("lbl-open-existing-vault", "open_existing_vault");
    translateLabel("lbl-load-sample", "load_sample");
    translateLabel("lbl-recent-vaults", "recent_vaults");
    translateLabel("lbl-new-entry", "new_entry");
    translateLabel("lbl-new-group", "new_group");
    translateLabel("lbl-all-items", "all_items");
    translateLabel("lbl-groups", "groups");
    translateLabel("lbl-export-json", "export_json");
    translateLabel("lbl-import-json", "import_json");
    translateLabel("modal-group-title", "add_group");
    translateLabel("lbl-group-name", "group_name");

    // Static dialog texts
    const saveLbl = document.getElementById("lbl-save");
    if (saveLbl) saveLbl.textContent = dict["save"] || "";

    const searchInput = document.getElementById("global-search-input") as HTMLInputElement;
    if (searchInput) {
      searchInput.placeholder = dict["search_placeholder"] || "";
    }

    // Refresh contents
    this.renderSidebar();
    this.renderEntryList();
    this.renderDetailsPanel();
  }

  private t(key: string, replacements: Record<string, string> = {}): string {
    const dict = this.loadedTranslations[this.currentLanguage] || this.loadedTranslations["en"] || {};
    let text = dict[key] || key;
    for (const [k, v] of Object.entries(replacements)) {
      text = text.replace(`{${k}}`, v);
    }
    return text;
  }

  // 5. THEME SWITCHING
  private initTheme() {
    const savedTheme = localStorage.getItem("kw_password_manager_theme") as "light" | "dark" || "light";
    this.setTheme(savedTheme);
  }

  private setTheme(theme: "light" | "dark") {
    this.theme = theme;
    localStorage.setItem("kw_password_manager_theme", theme);
    const html = document.documentElement;

    if (theme === "dark") {
      html.classList.add("dark");
    } else {
      html.classList.remove("dark");
    }
  }

  private toggleTheme() {
    this.setTheme(this.theme === "light" ? "dark" : "light");
  }

  // 6. UI & SPINNER REMOVAL
  private hideInitSpinner() {
    const spinner = document.getElementById("initial-spinner");
    if (spinner) {
      spinner.classList.add("opacity-0", "pointer-events-none");
      setTimeout(() => spinner.remove(), 400);
    }
  }

  // 7. FILE STUFF & VAULT MANAGEMENT
  private loadHistory() {
    const list = document.getElementById("recent-vault-list");
    if (!list) return;

    list.innerHTML = "";
    const key = "kw_password_vault_history";
    const historyJSON = localStorage.getItem(key);
    if (!historyJSON) {
      list.innerHTML = `<p id="lbl-no-recent-vaults" class="text-xs text-slate-400 font-medium">${this.t("no_recent_vaults")}</p>`;
      return;
    }

    try {
      const histories = JSON.parse(historyJSON) as Array<{ name: string; timestamp: string; data: VaultData }>;
      if (histories.length === 0) {
        list.innerHTML = `<p id="lbl-no-recent-vaults" class="text-xs text-slate-400 font-medium">${this.t("no_recent_vaults")}</p>`;
        return;
      }

      histories.forEach((h, index) => {
        const item = document.createElement("button");
        item.className = "w-full text-left p-2.5 rounded-xl text-xs flex items-center justify-between hover:bg-slate-100 dark:hover:bg-slate-800 border border-transparent hover:border-slate-200 dark:hover:border-slate-700 transition-all font-medium text-slate-600 dark:text-slate-300";
        item.innerHTML = `
          <div class="flex items-center gap-2 truncate">
            <i data-lucide="clock" class="w-3.5 h-3.5 shrink-0 text-sky-500"></i>
            <span class="font-bold truncate">${h.name}</span>
          </div>
          <span class="text-[10px] opacity-75 whitespace-nowrap">${new Date(h.timestamp).toLocaleDateString()}</span>
        `;
        item.addEventListener("click", () => {
          this.loadVaultData(h.data, h.name);
          this.showToast(`Restored vault: ${h.name}`);
        });
        list.appendChild(item);
      });
      // @ts-ignore
      if (window.lucide) window.lucide.createIcons();
    } catch (e) {
      list.innerHTML = `<p class="text-xs text-slate-400 font-medium">${this.t("no_recent_vaults")}</p>`;
    }
  }

  private saveHistory(name: string, data: VaultData) {
    const key = "kw_password_vault_history";
    let histories: Array<{ name: string; timestamp: string; data: VaultData }> = [];
    try {
      const existing = localStorage.getItem(key);
      if (existing) histories = JSON.parse(existing);
    } catch {}

    // Remove duplicates
    histories = histories.filter((h) => h.name !== name);
    histories.unshift({ name, timestamp: new Date().toISOString(), data });

    // Limit to top 5
    histories = histories.slice(0, 5);
    localStorage.setItem(key, JSON.stringify(histories));
    this.loadHistory();
  }

  private createNewVault() {
    const initialVault: VaultData = {
      vaultName: "My Password Vault",
      lastModified: new Date().toISOString(),
      groups: [
        { id: "group-personal", name: "Personal", icon: "user" },
        { id: "group-work", name: "Work", icon: "briefcase" },
        { id: "group-finance", name: "Finance", icon: "wallet" }
      ],
      entries: [
        {
          id: "entry-setup",
          groupId: "group-personal",
          title: "Sample Vault Config",
          username: "admin-user",
          password: "MySecurePassword123!",
          url: "https://localhost",
          notes: "Welcome! Feel free to replace this entry with your real accounts.",
          tags: ["admin", "welcome"],
          otpSecret: "JBSWY3DPEHPK3PXP",
          customFields: [{ name: "Demo-Key", value: "Demo-Value" }],
          created: new Date().toISOString(),
          modified: new Date().toISOString()
        }
      ]
    };
    this.loadVaultData(initialVault, "My Password Vault");
  }

  private async loadSampleVault() {
    try {
      // First try to fetch from external JSON
      const res = await fetch("./sample.json");
      if (res.ok) {
        const data = await res.json();
        this.loadVaultData(data, data.vaultName || "Demo Personal Vault");
        this.showToast("Sample loaded successfully!");
        return;
      }
    } catch {
      // Fail gracefully: fallback to direct simulation
    }

    // Direct fallback if fetch is not working (e.g. running outside server)
    const fallbackSamples = {
      vaultName: "Demo Personal Vault",
      lastModified: new Date().toISOString(),
      groups: [
        { id: "group-personal", name: "Personal", icon: "user" },
        { id: "group-work", name: "Work", icon: "briefcase" },
        { id: "group-finance", name: "Finance", icon: "wallet" },
        { id: "group-social", name: "Social Media", icon: "share2" }
      ],
      entries: [
        {
          id: "entry-google",
          groupId: "group-personal",
          title: "Google Account",
          username: "alex.doe@gmail.com",
          password: "gP$8wQ!Lm6Zt_Xy9",
          url: "https://accounts.google.com",
          notes: "Primary email and account used for personal communication.",
          tags: ["email", "critical", "google"],
          otpSecret: "JBSWY3DPEHPK3PXP",
          customFields: [
            { name: "Backup Codes Location", value: "Stored printed in safe" },
            { name: "Recovery Phone", value: "+1 (555) 019-2834" }
          ],
          created: "2026-01-10T12:00:00.000Z",
          modified: "2026-06-14T08:30:00.000Z"
        },
        {
          id: "entry-github",
          groupId: "group-work",
          title: "GitHub Enterprise",
          username: "alex-work-dev",
          password: "fK9#mN2&vX8_pL5q",
          url: "https://github.com",
          notes: "Work GitHub account used for developer repositories.",
          tags: ["developer", "work", "git"],
          otpSecret: "NBSWY3DPEHPK3PXP",
          customFields: [
            { name: "SSH Key Fingerprint", value: "SHA256:u1YfSgY8v6yP..." }
          ],
          created: "2026-02-14T09:15:00.000Z",
          modified: "2026-05-20T14:45:00.000Z"
        },
        {
          id: "entry-bank",
          groupId: "group-finance",
          title: "Chase Online Banking",
          username: "alex_chase_99",
          password: "vY3$zC7*bN1_mK8p",
          url: "https://www.chase.com",
          notes: "Personal checking and savings financial accounts.",
          tags: ["money", "finance", "banking"],
          otpSecret: "",
          customFields: [
            { name: "Account Number", value: "******4829" },
            { name: "Routing Number", value: "021000021" }
          ],
          created: "2026-01-05T10:30:00.000Z",
          modified: "2026-06-11T16:20:00.000Z"
        }
      ]
    };
    this.loadVaultData(fallbackSamples, "Demo Personal Vault");
    this.showToast("Loaded built-in offline sample vault");
  }

  private loadVaultData(data: VaultData, filename: string) {
    if (!data || !Array.isArray(data.groups) || !Array.isArray(data.entries)) {
      alert(this.t("error_invalid_vault"));
      return;
    }

    this.vault = data;
    this.vault.vaultName = data.vaultName || filename.replace(".json", "");
    this.selectedEntryId = null;
    this.selectedGroupId = "all";
    this.searchQuery = "";
    this.isEditingEntry = false;
    this.editEntryState = null;

    // Sync vault name in head input
    const nameInput = document.getElementById("vault-name-input") as HTMLInputElement;
    if (nameInput) nameInput.value = this.vault.vaultName;

    // Save recent history
    this.saveHistory(this.vault.vaultName, this.vault);

    // Swap screens
    document.getElementById("app-welcome")?.classList.add("hidden");
    document.getElementById("app-dashboard")?.classList.remove("hidden");

    // Redraw UI
    this.renderSidebar();
    this.renderEntryList();
    this.renderDetailsPanel();
  }

  private renameVault(newName: string) {
    if (!this.vault) return;
    const name = newName.trim() || this.t("untitled_vault");
    this.vault.vaultName = name;
    this.vault.lastModified = new Date().toISOString();
    this.saveHistory(name, this.vault);
  }

  private saveAndDownloadVault() {
    if (!this.vault) return;
    this.vault.lastModified = new Date().toISOString();

    const dataString = JSON.stringify(this.vault, null, 2);
    const blob = new Blob([dataString], { type: "application/json" });
    const filename = `${this.vault.vaultName.toLowerCase().replace(/[^a-z0-9]/g, "-")}-vault.json`;

    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);

    this.showToast(this.t("status_saved"));
    this.saveHistory(this.vault.vaultName, this.vault);
  }

  // 8. SIDEBAR RENDER
  private renderSidebar() {
    if (!this.vault) return;

    const groupList = document.getElementById("sidebar-group-list");
    if (!groupList) return;

    groupList.innerHTML = "";

    // Count badges
    const totalEntriesCount = this.vault.entries.length;
    const badgeAll = document.getElementById("badge-all-count");
    if (badgeAll) badgeAll.textContent = totalEntriesCount.toString();

    // Fill groups
    this.vault.groups.forEach((g) => {
      // Calculate active items count
      const itemsCount = this.vault!.entries.filter((e) => e.groupId === g.id).length;
      const isSelected = this.selectedGroupId === g.id;

      const btn = document.createElement("div");
      btn.className = `w-full flex items-center justify-between p-2 rounded-xl text-left text-sm font-medium transition-all group cursor-pointer ${
        isSelected
          ? "bg-sky-100 text-sky-800 dark:bg-sky-950/60 dark:text-sky-300"
          : "text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800"
      }`;

      btn.innerHTML = `
        <div class="flex items-center gap-2.5 min-w-0 pr-2 flex-grow truncate sidebar-click-target">
          <i data-lucide="${g.icon || 'folder'}" class="w-4 h-4 text-slate-400 shrink-0 ${isSelected ? 'text-sky-500' : ''}"></i>
          <span class="truncate">${g.name}</span>
        </div>
        <div class="flex items-center gap-1.5 shrink-0">
          <span class="text-[10px] bg-slate-100 dark:bg-slate-800/80 px-1.5 py-0.5 rounded text-slate-500 dark:text-slate-400 font-mono">${itemsCount}</span>
          <button class="btn-edit-group opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-400 hover:text-sky-500 transition-all" title="Edit Group">
            <i data-lucide="edit-3" class="w-3 h-3"></i>
          </button>
          <button class="btn-delete-group opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-400 hover:text-rose-500 transition-all" title="Delete Group">
            <i data-lucide="trash-2" class="w-3 h-3"></i>
          </button>
        </div>
      `;

      // Select group click handler
      btn.querySelector(".sidebar-click-target")?.addEventListener("click", () => {
        this.selectedGroupId = g.id;
        this.selectedEntryId = null;
        this.isEditingEntry = false;
        this.editEntryState = null;
        this.renderSidebar();
        this.renderEntryList();
        this.renderDetailsPanel();
      });

      // Edit click handler
      btn.querySelector(".btn-edit-group")?.addEventListener("click", (e) => {
        e.stopPropagation();
        this.openGroupModal(g);
      });

      // Delete click handler
      btn.querySelector(".btn-delete-group")?.addEventListener("click", (e) => {
        e.stopPropagation();
        if (confirm(this.t("delete_group_confirm"))) {
          this.deleteGroup(g.id);
        }
      });

      groupList.appendChild(btn);
    });

    // Sync header active filter label
    const activeFilterLbl = document.getElementById("lbl-active-group-filter");
    if (activeFilterLbl) {
      if (this.selectedGroupId === "all") {
        activeFilterLbl.textContent = this.t("all_items");
      } else {
        const found = this.vault.groups.find((g) => g.id === this.selectedGroupId);
        activeFilterLbl.textContent = found ? found.name : this.t("untitled_group");
      }
    }

    // Toggle active state for "All Items" sidebar button
    const sidebarAllBtn = document.getElementById("sidebar-btn-all");
    if (sidebarAllBtn) {
      if (this.selectedGroupId === "all") {
        sidebarAllBtn.className = "w-full flex items-center justify-between p-2.5 rounded-xl text-left text-sm font-semibold transition-all bg-sky-100 text-sky-800 dark:bg-sky-950/60 dark:text-sky-300 cursor-pointer";
        sidebarAllBtn.querySelector("i")?.classList.add("text-sky-500");
      } else {
        sidebarAllBtn.className = "w-full flex items-center justify-between p-2.5 rounded-xl text-left text-sm font-semibold transition-all text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 cursor-pointer";
        sidebarAllBtn.querySelector("i")?.classList.remove("text-sky-500");
      }
    }

    // @ts-ignore
    if (window.lucide) window.lucide.createIcons();
  }

  // 9. ENTRY CARDS LIST RENDER
  private renderEntryList() {
    if (!this.vault) return;

    const listContainer = document.getElementById("entry-list-container");
    if (!listContainer) return;

    listContainer.innerHTML = "";

    // 1. Filter entries
    let filtered = this.vault.entries;

    // Group filter
    if (this.selectedGroupId !== "all") {
      filtered = filtered.filter((e) => e.groupId === this.selectedGroupId);
    }

    // Search query filter
    if (this.searchQuery.trim().length > 0) {
      const q = this.searchQuery.toLowerCase();
      filtered = filtered.filter((e) => {
        return (
          e.title.toLowerCase().includes(q) ||
          e.username.toLowerCase().includes(q) ||
          e.url.toLowerCase().includes(q) ||
          e.notes.toLowerCase().includes(q) ||
          e.tags.some((t) => t.toLowerCase().includes(q))
        );
      });
    }

    // Sort entries
    if (this.sortingMode === "title") {
      filtered.sort((a, b) => a.title.localeCompare(b.title));
    } else {
      filtered.sort((a, b) => new Date(b.modified).getTime() - new Date(a.modified).getTime());
    }

    // If empty
    if (filtered.length === 0) {
      listContainer.innerHTML = `
        <div class="p-6 text-center text-slate-400 text-xs">
          <i data-lucide="info" class="w-8 h-8 mx-auto mb-2 opacity-50"></i>
          <span>${this.t("no_entries_found")}</span>
        </div>
      `;
      // @ts-ignore
      if (window.lucide) window.lucide.createIcons();
      return;
    }

    // Render cards
    filtered.forEach((e) => {
      const isSelected = this.selectedEntryId === e.id;
      const card = document.createElement("button");
      card.className = `w-full text-left p-3.5 rounded-2xl flex flex-col gap-1 border transition-all ${
        isSelected
          ? "bg-sky-50 text-sky-800 border-slate-200 dark:bg-sky-950/60 dark:text-sky-300"
          : "bg-slate-50 hover:bg-slate-100 dark:bg-slate-800/50 dark:hover:bg-slate-800 border-slate-100 dark:border-slate-800"
      }`;

      // Get tag elements
      const tagsHTML = e.tags
        .slice(0, 3)
        .map((t) => `<span class="px-1.5 py-0.5 rounded text-[10px] font-semibold border ${isSelected ? 'bg-sky-100 border-sky-200 text-sky-800 dark:bg-sky-900 dark:border-sky-800 dark:text-sky-300' : 'bg-slate-100 border-slate-200 text-slate-500 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-400'}">${t}</span>`)
        .join("");

      // Standard icon picker helper
      let domainIcon = "";
      if (e.url) {
        try {
          const u = new URL(e.url.startsWith("http") ? e.url : `https://${e.url}`);
          domainIcon = `<img src="https://www.google.com/s2/favicons?sz=64&domain=${u.hostname}" class="w-8 h-8 rounded-lg bg-white shrink-0 object-contain p-1 border shadow-xs" referrerPolicy="no-referrer" onerror="this.src='';" />`;
        } catch {
          domainIcon = `<div class="w-8 h-8 rounded-lg bg-sky-100 border text-sky-600 dark:bg-sky-950 dark:text-sky-300 flex items-center justify-center shrink-0 font-bold text-sm">${e.title.charAt(0).toUpperCase()}</div>`;
        }
      } else {
        domainIcon = `<div class="w-8 h-8 rounded-lg bg-sky-100 border text-sky-600 dark:bg-sky-950 dark:text-sky-300 flex items-center justify-center shrink-0 font-bold text-sm">${e.title.charAt(0).toUpperCase()}</div>`;
      }

      card.innerHTML = `
        <div class="flex items-center gap-3 w-full pr-1">
          ${domainIcon}
          <div class="flex-grow min-w-0">
            <h4 class="font-bold text-sm truncate ${isSelected ? 'text-sky-800 dark:text-sky-200' : 'text-slate-800 dark:text-white'}">${e.title || this.t("untitled_entry")}</h4>
            <p class="text-xs truncate ${isSelected ? 'text-slate-500 dark:text-slate-400' : 'text-slate-400'}">${e.username || "—"}</p>
          </div>
        </div>
        
        <div class="flex items-center justify-between mt-2.5 pt-2 border-t ${isSelected ? 'border-sky-200 dark:border-sky-850' : 'border-slate-100 dark:border-slate-800/50'}">
          <div class="flex gap-1 overflow-hidden max-w-[70%]">
            ${tagsHTML}
          </div>
          <span class="text-[9px] font-mono leading-none ${isSelected ? 'text-slate-500 dark:text-slate-400' : 'text-slate-400'}">${new Date(e.modified).toLocaleDateString()}</span>
        </div>
      `;

      card.addEventListener("click", () => {
        this.selectedEntryId = e.id;
        this.isEditingEntry = false;
        this.editEntryState = null;
        this.renderEntryList();
        this.renderDetailsPanel();
      });

      listContainer.appendChild(card);
    });

    // @ts-ignore
    if (window.lucide) window.lucide.createIcons();
  }

  // 10. DETAILED RIGHT PANEL RENDER
  private renderDetailsPanel() {
    const defaultPlaceholder = document.getElementById("details-default-placeholder");
    const viewBox = document.getElementById("details-view-box");

    if (!defaultPlaceholder || !viewBox) return;

    if (!this.vault || !this.selectedEntryId) {
      defaultPlaceholder.classList.remove("hidden");
      viewBox.classList.add("hidden");
      return;
    }

    defaultPlaceholder.classList.add("hidden");
    viewBox.classList.remove("hidden");

    // Fetch entry details load
    const activeEntry = this.vault.entries.find((e) => e.id === this.selectedEntryId);
    if (!activeEntry) {
      this.selectedEntryId = null;
      this.renderDetailsPanel();
      return;
    }

    if (this.isEditingEntry) {
      this.renderEditMode(activeEntry);
    } else {
      this.renderReadMode(activeEntry);
    }
  }

  // A. READ MODE LAYOUT Detail
  private renderReadMode(e: Entry) {
    const viewBox = document.getElementById("details-view-box");
    if (!viewBox) return;

    const groupObj = this.vault?.groups.find((g) => g.id === e.groupId);
    const categoryName = groupObj ? groupObj.name : "Unassigned";

    // Custom fields HTML
    let customFieldsHTML = "";
    if (e.customFields && e.customFields.length > 0) {
      customFieldsHTML = `
        <div class="space-y-3.5 border-t border-slate-200 dark:border-slate-800 pt-5">
          <h5 class="text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_custom_fields")}</h5>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            ${e.customFields
              .map(
                (f) => `
                <div class="p-3 bg-slate-100 dark:bg-slate-900 rounded-xl flex flex-col gap-1 relative border border-slate-200/50 dark:border-slate-800/50">
                  <span class="text-[10px] uppercase font-bold text-slate-400 tracking-wider">${f.name}</span>
                  <div class="flex items-center justify-between gap-2">
                    <span class="text-xs font-mono font-semibold select-all break-all pr-5 text-slate-700 dark:text-slate-300">${f.value}</span>
                    <button class="btn-copy-field absolute right-2.5 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-sky-500 hover:bg-slate-200 dark:hover:bg-slate-800 rounded transition-all" data-val="${f.value}">
                      <i data-lucide="copy" class="w-3.5 h-3.5"></i>
                    </button>
                  </div>
                </div>
              `
              )
              .join("")}
          </div>
        </div>
      `;
    }

    // OTP HTML block
    let otpBlock = "";
    if (e.otpSecret) {
      otpBlock = `
        <div class="p-4 bg-amber-500/5 dark:bg-amber-500/10 border border-amber-500/20 rounded-2xl flex flex-col md:flex-row gap-4 items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="p-2 bg-amber-500/20 text-amber-500 rounded-xl relative">
              <i data-lucide="shield-alert" class="w-5 h-5"></i>
              <!-- Loading Circle SVG visual countdown -->
              <svg class="absolute inset-0 w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path class="text-amber-500/10" stroke="currentColor" stroke-width="2" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                <path id="totp-progress-ring" class="text-amber-500 transition-all duration-1000 ease-linear" stroke="currentColor" stroke-width="2" stroke-dasharray="100, 100" fill="none" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
              </svg>
            </div>
            <div>
              <span class="text-[10px] font-bold text-amber-500 uppercase tracking-widest block">${this.t("totp_code")}</span>
              <div class="flex items-center gap-2">
                <span id="totp-digits-span" class="text-2xl font-mono font-bold tracking-widest text-slate-800 dark:text-amber-300">......</span>
                <span id="totp-timer-span" class="text-[10px] text-slate-400 font-mono">00s</span>
              </div>
            </div>
          </div>
          <button id="btn-copy-totp" class="flex items-center gap-1.5 bg-amber-500 hover:bg-amber-600 text-white text-xs font-bold px-3.5 py-2 rounded-xl transition-all shadow-md active:scale-95">
            <i data-lucide="copy" class="w-3.5 h-3.5"></i>
            <span id="lbl-copy-totp">Copy Code</span>
          </button>
        </div>
      `;
    }

    viewBox.innerHTML = `
      <div class="space-y-6">
        
        <!-- Header View Actions -->
        <div class="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
          <div class="flex items-center gap-3">
            <span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700">${categoryName}</span>
          </div>
          <div class="flex items-center gap-2">
            <button id="btn-edit-entry" class="flex items-center gap-1 px-3 py-1.5 bg-sky-500 hover:bg-sky-600 text-white text-xs font-semibold rounded-xl transition-all shadow-md active:scale-95">
              <i data-lucide="edit-3" class="w-3.5 h-3.5"></i>
              <span>${this.t("edit")}</span>
            </button>
            <button id="btn-delete-entry" class="flex items-center gap-1 px-3 py-1.5 bg-rose-500 text-white text-xs font-semibold rounded-xl hover:bg-rose-600 transition-all shadow-md active:scale-95">
              <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
              <span>${this.t("delete")}</span>
            </button>
          </div>
        </div>

        <!-- Title Display -->
        <div id="read-section-title" class="flex items-start gap-4">
          <div class="p-3.5 bg-sky-100 dark:bg-sky-950 text-sky-600 dark:text-sky-400 rounded-3xl shrink-0">
            <i data-lucide="fingerprint" class="w-8 h-8"></i>
          </div>
          <div class="min-w-0 flex-1">
            <h1 class="text-2xl font-bold tracking-tight text-slate-900 dark:text-white break-words">${e.title || this.t("untitled_entry")}</h1>
            <div class="flex flex-wrap gap-1.5 mt-2">
              ${e.tags
                .map((t) => `<span class="px-2 py-0.5 rounded-lg text-xs font-semibold bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200/50 dark:border-slate-800/10">${t}</span>`)
                .join("")}
            </div>
          </div>
        </div>

        <!-- Inputs Read cards -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-5 pt-4">
          
          <!-- Username card -->
          <div class="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/60 dark:border-slate-800 flex flex-col gap-1 relative shadow-sm">
            <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_username")}</span>
            <div class="flex items-center justify-between gap-2 mt-1">
              <span id="read-span-username" class="text-sm font-mono font-semibold break-all text-slate-700 dark:text-slate-200 select-all pr-6">${e.username || "—"}</span>
              ${e.username ? `
                <button class="btn-copy absolute right-3.5 top-1/2 -translate-y-1/2 p-1.5 text-slate-400 hover:text-sky-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-all" data-val="${e.username}">
                  <i data-lucide="copy" class="w-4 h-4"></i>
                </button>
              ` : ''}
            </div>
          </div>

          <!-- Password card -->
          <div class="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/60 dark:border-slate-800 flex flex-col gap-1 relative shadow-sm">
            <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_password")}</span>
            <div class="flex items-center justify-between gap-2 mt-1">
              <input type="password" id="read-input-password" value="${e.password}" class="text-sm font-mono font-semibold border-none bg-transparent p-0 w-full text-slate-700 dark:text-slate-200 focus:ring-0 disabled:opacity-100 select-all pr-12 cursor-default" readonly />
              <div class="absolute right-3.5 top-1/2 -translate-y-1/2 flex items-center gap-1">
                <button id="btn-toggle-password-view" class="p-1.5 text-slate-400 hover:text-sky-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-all">
                  <i data-lucide="eye" class="w-4 h-4"></i>
                </button>
                <button class="btn-copy p-1.5 text-slate-400 hover:text-sky-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-all" data-val="${e.password}">
                  <i data-lucide="copy" class="w-4 h-4"></i>
                </button>
              </div>
            </div>
          </div>

        </div>

        <!-- URL card -->
        ${e.url ? `
          <div class="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/60 dark:border-slate-800 flex items-center justify-between shadow-sm">
            <div class="flex-grow min-w-0">
              <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest block">${this.t("entry_url")}</span>
              <a href="${e.url.startsWith('http') ? e.url : 'https://' + e.url}" target="_blank" rel="noopener noreferrer" class="text-sm font-semibold text-sky-600 hover:text-sky-500 dark:text-sky-400 break-all select-all flex items-center gap-1.5 mt-1 underline">
                <i data-lucide="external-link" class="w-3.5 h-3.5 shrink-0"></i>
                <span class="truncate">${e.url}</span>
              </a>
            </div>
            <button class="btn-copy p-1.5 text-slate-400 hover:text-sky-500 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-all" data-val="${e.url}">
              <i data-lucide="copy" class="w-4.5 h-4.5"></i>
            </button>
          </div>
        ` : ''}

        <!-- OTP TOTP Code display -->
        ${otpBlock}

        <!-- Notes Card -->
        ${e.notes ? `
          <div class="p-4 bg-white dark:bg-slate-900 rounded-2xl border border-slate-200/60 dark:border-slate-800 flex flex-col gap-2 shadow-sm">
            <span class="text-[10px] font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_notes")}</span>
            <div class="text-sm text-slate-600 dark:text-slate-300 leading-relaxed whitespace-pre-wrap select-all bg-slate-50/50 dark:bg-slate-950/20 p-3 rounded-xl border border-slate-100 dark:border-slate-800">${e.notes}</div>
          </div>
        ` : ''}

        <!-- Custom Fields list -->
        ${customFieldsHTML}

        <!-- Modifications timestamp footer log -->
        <div class="flex flex-col md:flex-row md:items-center justify-between text-[10px] text-slate-400 border-t border-slate-100 dark:border-slate-800 pt-4 gap-2">
          <span>${this.t("created_at")}: <span class="font-bold">${new Date(e.created).toLocaleString()}</span></span>
          <span>${this.t("last_modified")}: <span class="font-bold">${new Date(e.modified).toLocaleString()}</span></span>
        </div>

      </div>
    `;

    // Hook listeners
    // Toggle password
    const toggleBtn = viewBox.querySelector("#btn-toggle-password-view");
    const pwdInput = viewBox.querySelector("#read-input-password") as HTMLInputElement;
    if (toggleBtn && pwdInput) {
      toggleBtn.addEventListener("click", () => {
        if (pwdInput.type === "password") {
          pwdInput.type = "text";
          toggleBtn.innerHTML = `<i data-lucide="eye-off" class="w-4 h-4"></i>`;
        } else {
          pwdInput.type = "password";
          toggleBtn.innerHTML = `<i data-lucide="eye" class="w-4 h-4"></i>`;
        }
        // @ts-ignore
        if (window.lucide) window.lucide.createIcons();
      });
    }

    // copy clipboard triggers
    viewBox.querySelectorAll(".btn-copy").forEach((b) => {
      b.addEventListener("click", () => {
        const value = b.getAttribute("data-val") || "";
        this.writeToClipboard(value);
      });
    });

    viewBox.querySelectorAll(".btn-copy-field").forEach((b) => {
      b.addEventListener("click", () => {
        const value = b.getAttribute("data-val") || "";
        this.writeToClipboard(value, "Custom field value copied!");
      });
    });

    // Copy TOTP trigger
    const copyTotpBtn = viewBox.querySelector("#btn-copy-totp");
    if (copyTotpBtn && e.otpSecret) {
      copyTotpBtn.addEventListener("click", () => {
        const activeCode = getTotp(e.otpSecret);
        this.writeToClipboard(activeCode, "TOTP Pin numeric token copied!");
      });
    }

    // Header edit & delete triggers
    viewBox.querySelector("#btn-edit-entry")?.addEventListener("click", () => {
      this.isEditingEntry = true;
      this.editEntryState = JSON.parse(JSON.stringify(e)); // deep clone
      this.renderDetailsPanel();
    });

    viewBox.querySelector("#btn-delete-entry")?.addEventListener("click", () => {
      if (confirm(this.t("delete_entry_confirm"))) {
        this.deleteEntry(e.id);
      }
    });

    // Run custom dynamic TOTP code updater instantly
    this.updateTOTPDisplays(e.otpSecret);

    // Refresh icons
    // @ts-ignore
    if (window.lucide) window.lucide.createIcons();
  }

  // B. EDIT MODE LAYOUT / CREATE MODE
  private renderEditMode(e: Entry) {
    const viewBox = document.getElementById("details-view-box");
    if (!viewBox || !this.vault) return;

    // Groups option picker list
    const groupOptions = this.vault.groups
      .map((g) => `<option value="${g.id}" ${g.id === e.groupId ? "selected" : ""}>${g.name}</option>`)
      .join("");

    // Custom Fields Editor List rows
    let cfEditorRows = "";
    if (e.customFields) {
      cfEditorRows = e.customFields
        .map(
          (field, idx) => `
        <div class="flex items-center gap-2 custom-field-editor-row" data-index="${idx}">
          <input type="text" value="${field.name}" placeholder="Field label" class="flex-1 bg-slate-100 dark:bg-slate-800 border-none px-3 py-2 rounded-xl text-xs font-semibold focus:bg-white dark:focus:bg-slate-700 field-name-input" />
          <input type="text" value="${field.value}" placeholder="Value" class="flex-2 bg-slate-100 dark:bg-slate-800 border-none px-3 py-2 rounded-xl text-xs font-semibold focus:bg-white dark:focus:bg-slate-700 field-value-input" />
          <button class="btn-delete-custom-field p-2 bg-rose-500/10 hover:bg-rose-500/20 text-rose-500 rounded-xl transition-colors" data-index="${idx}">
            <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
          </button>
        </div>
      `
        )
        .join("");
    }

    viewBox.innerHTML = `
      <div class="space-y-6">
        
        <!-- Header action bar -->
        <div class="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-4">
          <h2 class="text-lg font-bold flex items-center gap-2 text-slate-800 dark:text-white">
            <i data-lucide="edit-3" class="w-5 h-5 text-sky-500"></i>
            <span>${this.t("edit_group")}</span>
          </h2>
          <div class="flex items-center gap-2">
            <button id="btn-edit-cancel" class="px-4 py-1.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-white text-xs font-semibold rounded-xl transition-all active:scale-95">
              <span>${this.t("cancel")}</span>
            </button>
            <button id="btn-edit-save" class="px-4.5 py-1.5 bg-sky-500 hover:bg-sky-600 text-white text-xs font-semibold rounded-xl active:scale-95 transition-all shadow-md">
              <span>${this.t("save")}</span>
            </button>
          </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
          
          <!-- Title Input -->
          <div class="space-y-1.5 col-span-1 md:col-span-2">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_title")}</label>
            <input type="text" id="edit-input-title" value="${e.title}" placeholder="e.g. Gmail Login" class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold" />
          </div>

          <!-- Group select -->
          <div class="space-y-1.5">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("groups")}</label>
            <select id="edit-select-group" class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold">
              <option value="">(None - Unassigned)</option>
              ${groupOptions}
            </select>
          </div>

          <!-- Tags Input list raw -->
          <div class="space-y-1.5">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_tags")}</label>
            <input type="text" id="edit-input-tags" value="${e.tags.join(', ')}" placeholder="e.g. key, developers, finance" class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold" />
          </div>

          <!-- Username Input -->
          <div class="space-y-1.5">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_username")}</label>
            <input type="text" id="edit-input-username" value="${e.username}" placeholder="e.g. user@gmail.com" class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold" />
          </div>

          <!-- Password Input -->
          <div class="space-y-1.5">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_password")}</label>
            <div class="relative">
              <input type="text" id="edit-input-password" value="${e.password}" placeholder="Click generate or enter password" class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold font-mono pr-10" />
              <button id="btn-trigger-toggle-generator" class="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-sky-500 rounded-lg" title="Toggle Password Generator Tool">
                <i data-lucide="key-round" class="w-4 h-4"></i>
              </button>
            </div>
          </div>

          <!-- HIDDEN Password Generator embedded container panel -->
          <div id="password-generator-deck" class="hidden col-span-1 md:col-span-2 p-5 bg-slate-100 dark:bg-slate-900 rounded-2xl border border-slate-200/50 dark:border-slate-800 space-y-4 animate-fade-in shadow-inner">
            <div class="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2.5">
              <h4 class="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
                <i data-lucide="bolt" class="w-4 h-4 text-sky-500"></i>
                <span>${this.t("password_generator")}</span>
              </h4>
              <span id="lbl-gen-strength-badge" class="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded text-emerald-600 bg-emerald-500/10">Strong</span>
            </div>

            <!-- Parameters Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <!-- Slider length -->
              <div class="space-y-2">
                <div class="flex justify-between text-xs font-semibold text-slate-500">
                  <span>${this.t("length")}</span>
                  <span id="lbl-gen-length-value" class="font-bold text-slate-700 dark:text-white">16</span>
                </div>
                <input type="range" id="gen-slider-length" min="8" max="64" value="16" class="w-full cursor-pointer" />
              </div>

              <!-- Options check list -->
              <div class="space-y-2 font-semibold text-xs text-slate-600 dark:text-slate-300">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" id="gen-chk-upper" checked class="rounded border-slate-300 dark:bg-slate-800 accent-sky-500" />
                  <span>${this.t("include_uppercase")}</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" id="gen-chk-lower" checked class="rounded border-slate-300 dark:bg-slate-800 accent-sky-500" />
                  <span>${this.t("include_lowercase")}</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" id="gen-chk-numbers" checked class="rounded border-slate-300 dark:bg-slate-800 accent-sky-500" />
                  <span>${this.t("include_numbers")}</span>
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" id="gen-chk-symbols" checked class="rounded border-slate-300 dark:bg-slate-800 accent-sky-500" />
                  <span>${this.t("include_symbols")}</span>
                </label>
              </div>
            </div>

            <!-- Generate CTA -->
            <button id="btn-fire-generation" class="w-full py-2 bg-slate-200 hover:bg-slate-300 text-slate-700 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-white rounded-xl text-xs font-bold active:scale-98 transition-all flex items-center justify-center gap-2 shadow-xs">
              <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
              <span>${this.t("generate")}</span>
            </button>
          </div>

          <!-- URL Input -->
          <div class="space-y-1.5">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_url")}</label>
            <input type="text" id="edit-input-url" value="${e.url}" placeholder="e.g. https://github.com" class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold" />
          </div>

          <!-- OTP Secret (Base32) Input -->
          <div class="space-y-1.5">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_otp")}</label>
            <input type="text" id="edit-input-otp" value="${e.otpSecret}" placeholder="e.g. JBSWY3DPEHPK3PXP" class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-2.5 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold font-mono" />
          </div>

          <!-- Notes Textarea -->
          <div class="space-y-1.5 col-span-1 md:col-span-2">
            <label class="block text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_notes")}</label>
            <textarea id="edit-textarea-notes" rows="4" placeholder="Enter notes or recovery logs..." class="w-full bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800 px-4 py-3 rounded-xl text-sm focus:bg-white focus:ring-2 focus:ring-sky-500 text-slate-700 dark:text-white font-semibold">${e.notes}</textarea>
          </div>

        </div>

        <!-- Custom Fields Editor Section -->
        <div class="space-y-3.5 border-t border-slate-200 dark:border-slate-800 pt-5">
          <div class="flex items-center justify-between">
            <h5 class="text-xs font-bold text-slate-400 uppercase tracking-widest">${this.t("entry_custom_fields")}</h5>
            <button id="btn-add-custom-field" class="flex items-center gap-1.5 text-xs text-sky-600 dark:text-sky-400 hover:text-sky-500 font-bold transition-colors">
              <i data-lucide="plus" class="w-3.5 h-3.5"></i>
              <span>${this.t("add")}</span>
            </button>
          </div>

          <!-- Custom fields list box -->
          <div id="custom-fields-editor-container" class="space-y-2.5">
            ${cfEditorRows}
          </div>
        </div>

      </div>
    `;

    // Hook edit listeners
    const cancelBtn = viewBox.querySelector("#btn-edit-cancel");
    if (cancelBtn) {
      cancelBtn.addEventListener("click", () => {
        this.isEditingEntry = false;
        this.editEntryState = null;
        this.renderDetailsPanel();
      });
    }

    const saveBtn = viewBox.querySelector("#btn-edit-save");
    if (saveBtn) {
      saveBtn.addEventListener("click", () => {
        this.saveEntryDetails();
      });
    }

    // Toggle Password generator card
    const toggleGenBtn = viewBox.querySelector("#btn-trigger-toggle-generator");
    const genDeck = viewBox.querySelector("#password-generator-deck");
    if (toggleGenBtn && genDeck) {
      toggleGenBtn.addEventListener("click", () => {
        genDeck.classList.toggle("hidden");
      });
    }

    // Password generator logic slider
    const genSlider = viewBox.querySelector("#gen-slider-length") as HTMLInputElement;
    const genLenLbl = viewBox.querySelector("#lbl-gen-length-value");
    if (genSlider && genLenLbl) {
      genSlider.addEventListener("input", () => {
        genLenLbl.textContent = genSlider.value;
        this.updateGeneratorStrengthBadge();
      });
    }

    // Fire Generator
    const fireGenBtn = viewBox.querySelector("#btn-fire-generation");
    if (fireGenBtn) {
      fireGenBtn.addEventListener("click", () => {
        this.firePasswordGeneration();
      });
    }

    // Add Custom field click
    const addCFBtn = viewBox.querySelector("#btn-add-custom-field");
    if (addCFBtn) {
      addCFBtn.addEventListener("click", () => {
        this.addNewCustomFieldRow();
      });
    }

    // Hook Custom field values updates
    const cfContainer = viewBox.querySelector("#custom-fields-editor-container");
    if (cfContainer) {
      cfContainer.addEventListener("input", (ev) => {
        const target = ev.target as HTMLInputElement;
        const row = target.closest(".custom-field-editor-row") as HTMLElement;
        if (!row) return;

        const idx = parseInt(row.getAttribute("data-index") || "0");
        const nameInput = row.querySelector(".field-name-input") as HTMLInputElement;
        const valInput = row.querySelector(".field-value-input") as HTMLInputElement;

        if (this.editEntryState?.customFields[idx]) {
          this.editEntryState.customFields[idx].name = nameInput.value;
          this.editEntryState.customFields[idx].value = valInput.value;
        }
      });

      // Custom fields delete
      cfContainer.addEventListener("click", (ev) => {
        const btn = (ev.target as HTMLElement).closest(".btn-delete-custom-field");
        if (!btn) return;
        const idx = parseInt(btn.getAttribute("data-index") || "0");
        this.editEntryState?.customFields.splice(idx, 1);
        this.renderEditMode(this.editEntryState!);
      });
    }

    // @ts-ignore
    if (window.lucide) window.lucide.createIcons();
  }

  // 11. DYNAMIC TOTP BACKGROUND SYSTEM
  private startTOTPTimer() {
    setInterval(() => {
      if (!this.vault || !this.selectedEntryId || this.isEditingEntry) return;
      const activeEntry = this.vault.entries.find((e) => e.id === this.selectedEntryId);
      if (activeEntry && activeEntry.otpSecret) {
        this.updateTOTPDisplays(activeEntry.otpSecret);
      }
    }, 1000);
  }

  private updateTOTPDisplays(secret: string) {
    const epoch = Math.floor(Date.now() / 1000);
    const secondsRemaining = 30 - (epoch % 30);

    const digitsSpan = document.getElementById("totp-digits-span");
    const timerSpan = document.getElementById("totp-timer-span");
    const ring = document.getElementById("totp-progress-ring");

    if (digitsSpan) {
      const activeCode = getTotp(secret);
      // format spaces e.g. 123 456
      digitsSpan.textContent = activeCode.substr(0, 3) + " " + activeCode.substr(3, 3);
    }
    if (timerSpan) {
      timerSpan.textContent = this.t("totp_expires_in", { seconds: secondsRemaining.toString() });
    }

    // Circular Countdown SVG ring update
    if (ring) {
      const percentage = (secondsRemaining / 30) * 100;
      ring.setAttribute("stroke-dasharray", `${percentage}, 100`);
    }
  }

  // 12. PASSWORD GENERATOR HELPERS
  private updateGeneratorStrengthBadge() {
    const slider = document.getElementById("gen-slider-length") as HTMLInputElement;
    const badge = document.getElementById("lbl-gen-strength-badge");
    if (!slider || !badge) return;

    const val = parseInt(slider.value);
    if (val < 10) {
      badge.textContent = "Weak";
      badge.className = "text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded text-rose-600 bg-rose-500/10";
    } else if (val < 14) {
      badge.textContent = "Medium";
      badge.className = "text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded text-amber-600 bg-amber-500/10";
    } else {
      badge.textContent = "Strong";
      badge.className = "text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded text-emerald-600 bg-emerald-500/10";
    }
  }

  private firePasswordGeneration() {
    const passwordInput = document.getElementById("edit-input-password") as HTMLInputElement;
    if (!passwordInput) return;

    const length = parseInt((document.getElementById("gen-slider-length") as HTMLInputElement).value || "16");
    const useUpper = (document.getElementById("gen-chk-upper") as HTMLInputElement).checked;
    const useLower = (document.getElementById("gen-chk-lower") as HTMLInputElement).checked;
    const useNumbers = (document.getElementById("gen-chk-numbers") as HTMLInputElement).checked;
    const useSymbols = (document.getElementById("gen-chk-symbols") as HTMLInputElement).checked;

    let charset = "";
    if (useUpper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (useLower) charset += "abcdefghijklmnopqrstuvwxyz";
    if (useNumbers) charset += "0123456789";
    if (useSymbols) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

    if (charset.length === 0) {
      alert("Please select at least one character set!");
      return;
    }

    let pass = "";
    for (let i = 0; i < length; i++) {
      const idx = Math.floor(Math.random() * charset.length);
      pass += charset.charAt(idx);
    }

    passwordInput.value = pass;
    this.showToast("Secure password generated!");
  }

  // 13. CUSTOM FIELDS HELPERS
  private addNewCustomFieldRow() {
    if (!this.editEntryState) return;
    if (!this.editEntryState.customFields) {
      this.editEntryState.customFields = [];
    }
    this.editEntryState.customFields.push({ name: "New Field", value: "New Value" });
    this.renderEditMode(this.editEntryState);
  }

  // 14. ENTRY CRUD MOTIONS
  private createNewEntry() {
    if (!this.vault) return;

    const newId = "entry-" + Math.random().toString(36).substr(2, 9);
    const newEntry: Entry = {
      id: newId,
      groupId: this.selectedGroupId !== "all" ? this.selectedGroupId : "",
      title: "",
      username: "",
      password: "",
      url: "",
      notes: "",
      tags: [],
      otpSecret: "",
      customFields: [],
      created: new Date().toISOString(),
      modified: new Date().toISOString()
    };

    this.vault.entries.push(newEntry);
    this.selectedEntryId = newId;
    this.isEditingEntry = true;
    this.editEntryState = JSON.parse(JSON.stringify(newEntry));

    // Update list & views
    this.renderSidebar();
    this.renderEntryList();
    this.renderDetailsPanel();

    this.showToast("Empty entry draft created");
  }

  private saveEntryDetails() {
    if (!this.vault || !this.selectedEntryId || !this.editEntryState) return;

    // Gather latest static element inputs
    const editTitle = (document.getElementById("edit-input-title") as HTMLInputElement)?.value.trim() || "";
    const editGroup = (document.getElementById("edit-select-group") as HTMLSelectElement)?.value || "";
    const editUser = (document.getElementById("edit-input-username") as HTMLInputElement)?.value?.trim() || "";
    const editPass = (document.getElementById("edit-input-password") as HTMLInputElement)?.value || "";
    const editUrl = (document.getElementById("edit-input-url") as HTMLInputElement)?.value?.trim() || "";
    const editOtp = (document.getElementById("edit-input-otp") as HTMLInputElement)?.value?.trim() || "";
    const editNotes = (document.getElementById("edit-textarea-notes") as HTMLTextAreaElement)?.value || "";
    const editTagsRaw = (document.getElementById("edit-input-tags") as HTMLInputElement)?.value || "";

    // Parse Tags
    const tagsArray = editTagsRaw
      .split(",")
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    // Save state back to central store
    const idx = this.vault.entries.findIndex((ent) => ent.id === this.selectedEntryId);
    if (idx !== -1) {
      // Preserve dates
      const createdTime = this.vault.entries[idx].created;

      this.vault.entries[idx] = {
        id: this.selectedEntryId,
        groupId: editGroup,
        title: editTitle || this.t("untitled_entry"),
        username: editUser,
        password: editPass,
        url: editUrl,
        notes: editNotes,
        tags: tagsArray,
        otpSecret: editOtp,
        customFields: this.editEntryState.customFields,
        created: createdTime,
        modified: new Date().toISOString()
      };

      // Reset editing flags
      this.isEditingEntry = false;
      this.editEntryState = null;

      // Persist in history log instantly
      this.saveHistory(this.vault.vaultName, this.vault);

      // Redraw everything
      this.renderSidebar();
      this.renderEntryList();
      this.renderDetailsPanel();

      this.showToast("Changes saved safely to memory");
    }
  }

  private deleteEntry(id: string) {
    if (!this.vault) return;
    this.vault.entries = this.vault.entries.filter((en) => en.id !== id);
    this.selectedEntryId = null;
    this.isEditingEntry = false;
    this.editEntryState = null;

    // Save history
    this.saveHistory(this.vault.vaultName, this.vault);

    // Redraw
    this.renderSidebar();
    this.renderEntryList();
    this.renderDetailsPanel();

    this.showToast("Entry deleted successfully!");
  }

  // 15. GROUP CRUD MOTIONS
  private openGroupModal(targetGroup?: Group) {
    const modal = document.getElementById("modal-group");
    const backdrop = document.getElementById("modal-group-backdrop");
    const container = modal?.querySelector(".relative");

    if (!modal || !backdrop || !container) return;

    const modalTitle = document.getElementById("modal-group-title");
    const nameInput = document.getElementById("group-name-field") as HTMLInputElement;
    const idInput = document.getElementById("group-id-field") as HTMLInputElement;
    const saveBtn = document.getElementById("btn-group-modal-save");

    if (modalTitle && nameInput && idInput && saveBtn) {
      if (targetGroup) {
        // Edit group state
        modalTitle.textContent = this.t("edit_group");
        nameInput.value = targetGroup.name;
        idInput.value = targetGroup.id;
        saveBtn.textContent = this.t("save");
        this.setSelectedGroupIcon(targetGroup.icon || "folder");
      } else {
        // Create new group state
        modalTitle.textContent = this.t("add_group");
        nameInput.value = "";
        idInput.value = "";
        saveBtn.textContent = this.t("add");
        this.setSelectedGroupIcon("folder");
      }
    }

    // Toggle showing classes
    modal.classList.remove("hidden");
    setTimeout(() => {
      container.classList.remove("scale-95", "opacity-0");
      container.classList.add("scale-100", "opacity-100");
    }, 20);
  }

  private closeGroupModal() {
    const modal = document.getElementById("modal-group");
    const container = modal?.querySelector(".relative");

    if (!modal || !container) return;

    container.classList.remove("scale-100", "opacity-100");
    container.classList.add("scale-95", "opacity-0");
    setTimeout(() => {
      modal.classList.add("hidden");
    }, 200);
  }

  private setSelectedGroupIcon(icon: string) {
    const picker = document.getElementById("group-icon-picker");
    if (!picker) return;

    picker.querySelectorAll("button").forEach((btn) => {
      const attr = btn.getAttribute("data-icon");
      if (attr === icon) {
        btn.className = "p-2.5 rounded-xl border border-sky-500 bg-sky-50 dark:bg-sky-950/60 text-sky-500 flex items-center justify-center hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors";
      } else {
        btn.className = "p-2.5 rounded-xl border border-slate-200 dark:border-slate-800 text-slate-400 flex items-center justify-center hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors";
      }
    });
  }

  private saveModalGroup() {
    if (!this.vault) return;

    const nameInput = document.getElementById("group-name-field") as HTMLInputElement;
    const idInput = document.getElementById("group-id-field") as HTMLInputElement;
    const picker = document.getElementById("group-icon-picker");

    if (!nameInput) return;

    const name = nameInput.value.trim();
    if (!name) {
      alert("Group name cannot be empty!");
      return;
    }

    // Find selected icon
    let icon = "folder";
    picker?.querySelectorAll("button").forEach((b) => {
      if (b.classList.contains("border-sky-500")) {
        icon = b.getAttribute("data-icon") || "folder";
      }
    });

    const existingGroupId = idInput.value;

    if (existingGroupId) {
      // Update
      const groupIdx = this.vault.groups.findIndex((g) => g.id === existingGroupId);
      if (groupIdx !== -1) {
        this.vault.groups[groupIdx].name = name;
        this.vault.groups[groupIdx].icon = icon;
        this.showToast(`Updated group: ${name}`);
      }
    } else {
      // Create new
      const newId = "group-" + Math.random().toString(36).substr(2, 9);
      this.vault.groups.push({
        id: newId,
        name: name,
        icon: icon
      });
      this.showToast(`Created group: ${name}`);
    }

    // Persist
    this.vault.lastModified = new Date().toISOString();
    this.saveHistory(this.vault.vaultName, this.vault);

    // Redraw and close modal
    this.renderSidebar();
    this.renderEntryList();
    this.closeGroupModal();
  }

  private deleteGroup(groupId: string) {
    if (!this.vault) return;

    // Filter group array
    this.vault.groups = this.vault.groups.filter((g) => g.id !== groupId);

    // Unassign entries matching deleted group category
    this.vault.entries.forEach((e) => {
      if (e.groupId === groupId) e.groupId = "";
    });

    // Reset filtering
    if (this.selectedGroupId === groupId) {
      this.selectedGroupId = "all";
      this.selectedEntryId = null;
    }

    this.vault.lastModified = new Date().toISOString();
    this.saveHistory(this.vault.vaultName, this.vault);

    // Redraw
    this.renderSidebar();
    this.renderEntryList();
    this.renderDetailsPanel();

    this.showToast("Group removed successfully!");
  }

  // 16. TOAST MECHANISM
  private showToast(text: string) {
    const toast = document.getElementById("toast-notification");
    const toastText = document.getElementById("toast-text");

    if (!toast || !toastText) return;

    toastText.textContent = text;
    toast.classList.remove("translate-y-20", "opacity-0");
    toast.classList.add("translate-y-0", "opacity-100");

    // timeout
    setTimeout(() => {
      toast.classList.remove("translate-y-0", "opacity-100");
      toast.classList.add("translate-y-20", "opacity-0");
    }, 2800);
  }

  private writeToClipboard(text: string, msg: string = "Copied to clipboard!") {
    if (!text) return;
    navigator.clipboard.writeText(text).then(
      () => this.showToast(msg),
      (err) => alert("Failed to copy clipboard: " + err)
    );
  }

  // 17. MAIN DOM BINDINGS CONFIG
  private bindEvents() {
    // Welcome Actions
    document.getElementById("btn-create-vault")?.addEventListener("click", () => {
      this.createNewVault();
    });

    document.getElementById("btn-load-sample")?.addEventListener("click", () => {
      this.loadSampleVault();
    });

    // Opening Vault File uploads Fallback
    const uploadInput = document.getElementById("file-vault-upload") as HTMLInputElement;
    document.getElementById("btn-open-vault")?.addEventListener("click", () => {
      uploadInput.click();
    });

    uploadInput?.addEventListener("change", (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (re) => {
        try {
          const parsed = JSON.parse(re.target?.result as string);
          this.loadVaultData(parsed, file.name);
          this.showToast(`Opened raw file: ${file.name}`);
        } catch {
          alert("Invalid JSON upload error!");
        }
      };
      reader.readAsText(file);
    });

    // Sidebar Items Click
    document.getElementById("sidebar-btn-all")?.addEventListener("click", () => {
      this.selectedGroupId = "all";
      this.selectedEntryId = null;
      this.isEditingEntry = false;
      this.editEntryState = null;
      this.renderSidebar();
      this.renderEntryList();
      this.renderDetailsPanel();
    });

    // Add New Group Clicking
    document.getElementById("btn-add-group")?.addEventListener("click", () => {
      this.openGroupModal();
    });

    document.getElementById("btn-new-group-top")?.addEventListener("click", () => {
      this.openGroupModal();
    });

    // Sidebar Import JSON Vault Actions
    const fileImportInput = document.getElementById("file-import-upload") as HTMLInputElement;
    document.getElementById("btn-import-vault")?.addEventListener("click", () => {
      fileImportInput.click();
    });

    fileImportInput?.addEventListener("change", (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (re) => {
        try {
          const data = JSON.parse(re.target?.result as string);
          this.loadVaultData(data, data.vaultName || file.name);
          this.showToast(`Successfully Imported ${file.name}`);
        } catch {
          alert(this.t("error_invalid_vault"));
        }
      };
      reader.readAsText(file);
    });

    // Sidebar Export JSON Vault Actions Clicking
    document.getElementById("btn-export-vault")?.addEventListener("click", () => {
      this.saveAndDownloadVault();
    });

    // Save Vault Click in Header
    document.getElementById("btn-save-vault")?.addEventListener("click", () => {
      this.saveAndDownloadVault();
    });

    // Rename Vault Action
    const nameInput = document.getElementById("vault-name-input") as HTMLInputElement;
    nameInput?.addEventListener("blur", () => {
      this.renameVault(nameInput.value);
    });
    nameInput?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        nameInput.blur();
      }
    });

    // Global Search Action
    const searchInput = document.getElementById("global-search-input") as HTMLInputElement;
    searchInput?.addEventListener("input", () => {
      this.searchQuery = searchInput.value;
      this.renderEntryList();
    });

    // Add New Entry Button Trigger Clicking
    document.getElementById("btn-new-entry")?.addEventListener("click", () => {
      this.createNewEntry();
    });

    // Sort Sorting Header Option action
    const sortBtn = document.getElementById("btn-sort");
    const sortTitle = document.getElementById("lbl-sort-title");
    sortBtn?.addEventListener("click", () => {
      if (this.sortingMode === "title") {
        this.sortingMode = "modified";
        if (sortTitle) sortTitle.textContent = this.t("last_modified");
      } else {
        this.sortingMode = "title";
        if (sortTitle) sortTitle.textContent = this.t("entry_title");
      }
      this.renderEntryList();
    });

    // Language Dropdown selectors
    document.getElementById("welcome-lang-select")?.addEventListener("change", (e) => {
      this.setLanguage((e.target as HTMLSelectElement).value);
    });

    document.getElementById("dashboard-lang-select")?.addEventListener("change", (e) => {
      this.setLanguage((e.target as HTMLSelectElement).value);
    });

    // Theme Switch action buttons
    document.getElementById("welcome-btn-theme")?.addEventListener("click", () => {
      this.toggleTheme();
    });

    document.getElementById("dashboard-btn-theme")?.addEventListener("click", () => {
      this.toggleTheme();
    });

    // Logout Click
    document.getElementById("btn-logout")?.addEventListener("click", () => {
      this.vault = null;
      this.selectedEntryId = null;
      document.getElementById("app-dashboard")?.classList.add("hidden");
      document.getElementById("app-welcome")?.classList.remove("hidden");
      this.loadHistory();
      this.showToast("Vault Locked & Locked Safely!");
    });

    // Modal Group Actions BindINGS
    document.getElementById("modal-group-backdrop")?.addEventListener("click", () => {
      this.closeGroupModal();
    });

    document.getElementById("btn-group-modal-cancel")?.addEventListener("click", () => {
      this.closeGroupModal();
    });

    document.getElementById("btn-group-modal-save")?.addEventListener("click", () => {
      this.saveModalGroup();
    });

    // Modal select group icon pickers click event mapping
    const picker = document.getElementById("group-icon-picker");
    picker?.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        const iconAttr = btn.getAttribute("data-icon") || "folder";
        this.setSelectedGroupIcon(iconAttr);
      });
    });
  }
}

// 18. INITIALIZE LAUNCHER BOOT-UP EVENT
document.addEventListener("DOMContentLoaded", () => {
  new AppManager();
});
