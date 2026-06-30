# Project: Silent Auction Manager (SAM)

This project uses standard prompts stored in "Z:\Backup\Websites\Claude\StandardPrompts.md"

Always read the instructions in "Z:\Backup\Websites\Web Utilities\components\table\readme.md"
Always read the instructions in "Z:\Backup\Websites\Web Utilities\components\toolbar\readme.md"

---

## What This App Does

A browser-based silent auction management tool for the East Tennessee Corvette Club (ETCC). It runs entirely in the browser with no backend — all data is stored in localStorage. Members use it to manage the full auction lifecycle from item intake through payment and pickup.

The app is accessed at: https://etccapps.com/apps/samtest

---

## File Structure

```
index.html          — Entire application (single-page app, all JS inline)
test.html           — Regression test suite (388 tests: logic + UI suites)
css/table.css       — TableKit component (do not modify)
css/toolbar.css     — PageToolbar component (do not modify)
js/table.js         — TableKit component (do not modify)
js/toolbar.js       — PageToolbar component (do not modify)
Images/
  ETCClogoWhiteBackground.png  — ETCC logo used in hero and home screen
```

---

## Architecture

- **Single HTML file** — all application logic, styles, and markup are in `index.html`
- **No backend, no database** — all data persists in browser `localStorage`
- **localStorage keys:**
  - `sam_items`    — auction items array
  - `sam_bidders`  — bidders array
  - `sam_winners`  — winners object keyed by item_number
  - `sam_payments` — payments object keyed by bidder_number
  - `sam_settings` — settings object
  - `sam_fieldmap` — email field mapping array
- **Gmail integration** — uses Google Identity Services (GIS) OAuth2 + Gmail API to scan the auction inbox
- **Google OAuth Client ID:** `215529370659-28knl9jlure9gells5aedltglbpdrgt4.apps.googleusercontent.com`
- **Auction email account:** `etccwebsite.auction@gmail.com`

---

## Navigation Structure

The app has a fixed left nav (220px) and a main content area. Screens are shown/hidden via `.screen.active`. Nav items use `data-screen` attributes and call `navigate()`.

### Screens (in order)
| Screen ID            | Nav Label              | Step |
|----------------------|------------------------|------|
| `screen-home`        | Home                   | —    |
| `screen-item-load`   | Load Item Emails       | 1    |
| `screen-bidding-sheets` | Create Bid Sheets   | 2    |
| `screen-bidder-reg`  | Register Bidders       | 3    |
| `screen-auction-close` | Record Winning Bidders| 4   |
| `screen-winner-announce` | Announce Winners   | 5    |
| `screen-payment-pickup` | Pay & Pickup        | 6    |
| `screen-post-auction`| Post Auction           | 7    |
| `screen-settings`    | Settings               | —    |

### Modals
- `view-all-modal` — Full-screen view of emails or items
- `cat-modal` — Category list view
- `cat-items-modal` — Items within a category
- `email-modal` — Individual email preview
- `manual-overlay` — User manual
- `bidder-edit-modal` — Edit bidder details

---

## Item Categories

Items are numbered as `{categoryCode}-{sequence}` (e.g., `200-3`):

| Code | Category |
|------|----------|
| 100  | General Auto Repair / Car Items |
| 200  | Corvette Items |
| 300  | Men's Items |
| 400  | Women's Items |
| 500  | General Household |
| 600  | Framed Artwork or other Artwork to be Hung |
| 700  | Baskets / Gift Sets |
| 800  | Gift Certificates |
| 900  | Miscellaneous / Other |

---

## Key Data Structures

**Item object:**
```js
{
  item_number,        // e.g. "200-3"
  email_message_id,   // Gmail message ID (used for duplicate detection)
  item_category,      // category name string
  description,        // item description
  item_value,         // value string e.g. "$25.00"
  reserve_amount,     // reserve string
  donor_name,
  donor_email,
  donor_phone,
  submission_date,
  date_loaded         // ISO string
}
```

**Bidder object:**
```js
{ bidder_number, last_name, first_name, email, phone }
```

**Winners object:** `{ "200-1": { bidder_number, bidder_name, winning_bid } }`

**Payments object:** `{ 1: { checknum, method, paid, other, otherReason } }`

**Settings object:**
```js
{
  gmailClientId, inboxEmail, debugMode,
  startingBidPct: 30, finalBidPct: 150, bidCount: 25,
  emailFolder: 'INBOX', squarePct: 2.6, squareFee: 0.10
}
```

---

## Email Field Mapping

Items are parsed from Gmail emails using a configurable field map (`sam_fieldmap`). Each entry maps an email label to a database column using one of three extraction modes:
- `Next Line` — value is on the next line after the label
- `Current Line to End` — value follows the label on the same line
- `Current Line to Comma` — value follows the label, stops at first comma

---

## Bid Sheet Logic

- Starting bid = `item_value × (startingBidPct / 100)`
- Final bid = `item_value × (finalBidPct / 100)`
- Bid rows evenly increment from starting to final bid
- `bidCount` controls number of rows (default 25)
- If `reserve_amount` is set and non-zero, it overrides `item_value` as the bid base

---

## Square / Credit Card Calculations

- CC transaction fee = `totalBid × (squarePct / 100) + squareFee`
- CC total = `totalBid + ccTransactionFee`
- Amount due = CC total (if Credit Card) or totalBid (if Cash/Check)

---

## Component Rules

### TableKit (`css/table.css`, `js/table.js`)
- Every `<table>` must have `class="tablekit"`
- Call `TableKit.initAll()` inside `DOMContentLoaded`
- Never apply custom inline styles to tables
- Do not modify `table.css` or `table.js`

### PageToolbar (`css/toolbar.css`, `js/toolbar.js`)
- Call `PageToolbar.init({ title: '...', logoText: '...' })` after `TableKit.initAll()`
- Do not modify `toolbar.css` or `toolbar.js`

### Toolbar palette overrides (applied via CSS in index.html)
```css
.tk-toolbar              { background: var(--nav-bar); }
.tk-toolbar-logo-text    { color: var(--accent); }
.tk-toolbar-title        { color: #ffffff; }
.tk-btn                  { background: var(--bg-section); border-color: var(--border); color: var(--text); }
.tk-btn:hover            { background: var(--accent); border-color: var(--accent-hover); color: #fff; }
.tk-btn-close            { border-color: var(--danger); color: var(--danger); }
.tk-btn-close:hover      { background: var(--danger); color: #fff; }
```

---

## Palette (CSS Variables)

```css
--bg:             #ffffff
--bg-dark:        #000000
--bg-section:     #f5f5f7
--text:           #1d1d1f
--text-secondary: #6e6e73
--text-tertiary:  #86868b
--accent:         #0071e3
--accent-hover:   #0077ed
--border:         #d2d2d7
--nav-bar:        #1d1d1f
--danger:         #c62828
--success:        #1a7f37
```

**Table headers:** `background: #dbeafe`, sticky, `color: var(--text)`
**Alternating rows:** even = `#f0f7ff`, odd = `#ffffff`

---

## Regression Tests

- Test file: `test.html`
- **388 tests** in two phases:
  - **Logic suites** (~179 tests): pure-function checks — email parsing, item numbering, bidder CRUD, bid calculations, Square fee math, payment logic, winner logic, sort indicators, home metrics, invoice calculations
  - **UI suites**: run the real app inside an `<iframe src="index.html">` and exercise each screen (navigation, View All modals, checkboxes, buttons, etc.)
- **Always run via the deployed URL:** https://etccapps.com/apps/samtest/test.html
  - The UI suites require the app to be framable. The server CSP (`.htaccess`)
    must include `frame-src 'self'` — without it the iframe is blocked and the
    suite hangs at "Running UI tests… 179".
  - Do not run the local headless runner against a plain static server for
    sign-off; it doesn't reproduce the live CSP/server-sync environment.
- Run from: Settings → Developer Tools → Run Regression Tests (opens in new tab)
- **Always run regression tests before reporting any task complete**
- When `test.html` changes, deploy it (`.\deploy.ps1 test.html`) before running,
  so the deployed suite reflects the latest tests.

---

## Deployment

- Host: Hostinger
- URL: https://etccapps.com/apps/sam
- Deploy whenever files are changed (per StandardPrompts rules)
- Always clearly indicate when files have been deployed

---

## Standard Rules (from StandardPrompts.md)

- Protect existing working features — do not delete or rewrite large sections unless necessary
- Before coding, identify affected files and possible side effects
- Use the existing project structure and coding style (inline JS in index.html, no frameworks)
- After changes, provide a regression test checklist
- Only commit, push, or deploy when explicitly given a checkpoint command
- When a checkpoint is given: update regression tests, run them, prompt whether to commit and push
- Clearly indicate when a change has been deployed
- Instrument all code by creating an error.log
- Whenever a checkpoint prompt is given with no description, use a good short name
