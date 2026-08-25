# mfa-auth

自建（非 Auth0／Cognito）的本機 MVP：**email／密碼 + 強制 TOTP MFA + 單次備援碼 + 伺服器端 session**。  
Stack：Express、SQLite（`better-sqlite3`）、Vitest／Supertest。

本 README 同時當作「交接文件」與作業說明：別人應能不靠口頭詢問就跑起來，並看懂取捨。

---

## Quick start（不用問就能跑）

需求：Node.js 18+（Windows 上 `argon2`／`better-sqlite3` 需要可用的 C++ 建置環境）。

```bash
npm install
npm run migrate
npm run seed          # 寫入試玩帳號（可重複執行，已存在會 skip）
npm test              # 應全綠
npm start             # http://localhost:3000
```

- 瀏覽器試玩：開 [http://localhost:3000/](http://localhost:3000/)（極簡 HTML，幾乎無 CSS）
- API 文件與 curl：見下方「API」
- 環境變數範例：[`.env.example`](.env.example)（**程式不會自動載入 `.env`**，請用 shell export 或接受預設值）

| 變數 | 用途 | 預設 |
| --- | --- | --- |
| `PORT` | HTTP port | `3000` |
| `DATABASE_PATH` | SQLite 路徑 | `./data/app.sqlite` |
| `MFA_ENCRYPTION_KEY` | AES-256 金鑰（64 hex = 32 bytes） | 64 個 `0`（僅本機） |
| `COOKIE_SECURE` | 設 `true` 才開 Secure cookie | 未設（本機 HTTP 可帶 cookie） |

試玩帳號（密碼皆 `password12345`）：

- `alice@example.com`、`bob@example.com`、`carol@example.com`
- `test01@example.com` … `test20@example.com`

PowerShell 請用 `curl.exe`；Git Bash 用 `curl` 即可。

---

## 使用者流程（強制 MFA）

1. **註冊** `POST /signup` → 只有帳號，尚未登入。  
2. **第 1 次登入**（尚未開 MFA）→ 密碼正確後**自動 enroll**，回傳 `MFA_ENROLLMENT_REQUIRED` + QR，並設 `sid`；此時 `GET /me` 為 **403**。  
3. **Confirm** `POST /mfa/confirm` → `mfa_enabled=true`，備援碼**只顯示一次**；之後 `/me` 才 200。  
4. **第 2 次起登入** → 密碼正確後回 `MFA_REQUIRED` + `mfa_token`（**不發**完整 session）；`POST /mfa/verify` 用 TOTP 或備援碼後才發新的 `sid`。  
5. **Logout** → 伺服器 `revoked_at`，cookie 失效。

---

## 一、題目沒寫的部分：我補了什麼、為什麼、刻意不做什麼

題目／PRD 多半只列功能名（signup、login、TOTP、backup、logout、rate limit）。上線前還差「狀態機、失敗模式、可測性、可交接」。以下是我判斷後補上的。

### 有補、且為什麼

| 補上的點 | 為什麼補 |
| --- | --- |
| **強制 MFA**（登入未開 MFA 時自動 QR；Confirm 前 `/me` 回 403） | 若 MFA 可選，等於一半帳號仍是「單因子」。身分系統應預設高安全水位。 |
| **Pending MFA token**（`MFA_REQUIRED` 時不發完整 `sid`） | 密碼對 ≠ 登入完成；否則第二因子形同虛設。 |
| **Session token 只存 SHA-256** | DB 外洩時不能直接拿 cookie 登入。 |
| **TOTP 種子 AES-256-GCM** | 種子與密碼同等敏感；不能明文躺在 SQLite。 |
| **同一步 TOTP 不可重放** | 降低重放／並發驗證的窗口。 |
| **登入錯誤一律 `Invalid credentials`** | 減少帳號枚舉。 |
| **不存在的使用者仍走 Argon2 verify** | 降低 timing 差異。 |
| **Audit log**（成功／失敗／MFA／備援碼） | 出事時要有痕跡；也方便之後接告警。 |
| **Rate limit 可注入 clock** + **TOTP 測試注入已知 secret** | 資安行為必須可測，否則只能「感覺安全」。 |
| **TDD 切片 + Conventional Commits** | 讓接手的人看得出決策順序，而不是一顆巨大 dump。 |
| **極簡 HTML + `npm run seed`** | 題目允許 curl；補 UI 是為了降低「別人跑不起來／不知道怎麼測 MFA」的摩擦。 |

### 想到但決定不做（與原因）

| 不做 | 原因 |
| --- | --- |
| Auth0／Clerk／Cognito 整包 IdP | 題目要自建生命週期；外包等於交白卷。只用**密碼雜湊／TOTP／DB** 函式庫，身分狀態機自己寫。 |
| Passkeys／WebAuthn | 抗釣魚更好，但 RP ID、瀏覽器實測超出 MVP 時程；TOTP 已能證明 challenge／加密／恢復碼。 |
| SMS／Email OTP 當主 MFA | SIM swap、信箱＝重設通道、成本與投遞；不適合作主因子。 |
| 忘記密碼／Email 驗證 | 最容易做成「繞過 MFA」；沒時間做對就寧可不做半套。 |
| Logout-all、裝置列表、信任裝置 | PRD 只要單 session 撤銷；多裝置產品化要額外威脅模型。 |
| Redis／KMS／多實例 | 本機單進程 MVP；記憶體 rate limit／pending token 可接受。 |
| 華麗前端 | 擴大攻擊面與時程，對驗證核心幫助小。 |

---

## 二、風險評估：優先處理什麼、沒處理什麼

這是身分系統，會被當成攻擊面。有限時間內無法覆蓋一切；以下是優先序與理由。

### 優先處理（已做或做到「夠用」）

| 風險 | 優先原因 | 本專案怎麼對 |
| --- | --- | --- |
| **密碼外洩／離線破解** | 一旦 DB dump，影響最大 | Argon2id；回應不回傳 hash |
| **Session 竊取後無法撤銷** | 長效 JWT 登出無效 | Opaque cookie + DB `revoked_at`；token 存 hash |
| **略過第二因子** | MFA 形式主義 | 強制 enroll；`MFA_REQUIRED` 前不發完整 session；Confirm 前 `/me` 403 |
| **Credential stuffing／暴力嘗試** | 網路上最常見 | 每 email／每 IP 失敗次數 + 暫時鎖定；鎖定期跳過 Argon2 |
| **TOTP 種子外洩** | 等同永久第二因子失守 | AES-256-GCM at rest |
| **備援碼變成第二密碼庫** | 明文備援碼＝後門 | 只顯示一次；SHA-256；單次使用 + audit |
| **Session fixation** | 舊 cookie 綁上新登入 | MFA verify 後發新 session |
| **帳號枚舉** | 幫助攻擊者建名單 | 泛用錯誤訊息 |

### 有意識沒處理（或只做到一半）與原因

| 風險 | 為什麼這輪不做／只做一半 |
| --- | --- |
| **釣魚（phishing）針對 TOTP** | 正確解是 WebAuthn；時程上用 TOTP 換「可完成的 MFA」 |
| **XSS 偷 cookie** | HttpOnly 有擋 JS 讀取；完整還要 CSP、模板安全——本專案幾乎無服務端 HTML 模板 |
| **CSRF** | SameSite=Lax 對同站表單有幫助；未做 double-submit／CSRF token（API＋fetch same-origin demo） |
| **程序重啟後 rate limit／pending MFA 消失** | 單機 demo；上線應遷 Redis |
| **金鑰管理／輪替** | env 固定 key；上線要 KMS |
| **帳號恢復社會工程**（客服重置 MFA） | 沒有人工流程就做「email 重設」反而更危險 |
| **多裝置失竊清場** | 無 logout-all |
| **進階濫用**（驗證碼轰炸、住宅代理、慢速噴射） | 僅基礎限流 |

### 現成套件／服務：它做了什麼、我做了什麼

**沒有**使用完整驗證服務（Auth0、Firebase Auth、Cognito、Clerk 等）。

使用的函式庫分工：

| 依賴 | 它處理的風險／能力 | 我仍要自己負責的 |
| --- | --- | --- |
| `argon2` | 記憶體困難雜湊演算法本身 | 何時 hash／verify、dummy hash、政策 |
| `otpauth` | TOTP 演算法與 otpauth URI | 註冊狀態機、加密存放、重放、與 login 銜接 |
| `qrcode` | QR 編碼 | 何時發給使用者、勿回傳明文 secret |
| `better-sqlite3` | 本機 persistence | schema、交易語意、備份、移轉 |
| `express` + `cookie-parser` | HTTP／cookie 解析 | Cookie 旗標、CSRF 策略、授權中介層 |

結論：**密碼學原語用庫；身分生命週期、威脅邊界、可否繞過 MFA，都是應用層責任。**

---

## 三、協作：commit 與 README 怎麼讓別人接手

### Git

以功能切片提交，訊息採 Conventional Commits，方便 `git log` 還原決策：

1. `chore: initialize project scaffold and database schema`
2. `feat(auth): implement signup, password login, session cookie, and logout`
3. `feat(security): implement rate limiting, lockout, and audit logs`
4. `feat(mfa): implement TOTP enrollment, confirmation, and login challenge`
5. `feat(recovery): implement single-use hashed backup codes`
6. `docs: complete README with setup guide, curl examples, and security architecture`
7. `chore: add demo seed accounts and minimal browser UI`
8. `feat(mfa): force TOTP enrollment on first login with auto QR`

原則：每個 slice **先測後實作、測試綠了才 commit**；不把半套 MFA 與 session 混在同一顆無法 review 的 commit。

### README／可跑性

- 上方 Quick start：`install → migrate → seed → test → start`
- 瀏覽器與 curl 兩條路
- 本文件其餘章節說明「為什麼這樣做」，減少口頭交接

過程中的產品問題（例如 Confirm 前是否擋 `/me`）會直接影響威脅模型，應先問清楚再寫死——多問不扣分，亂猜才貴。

---

## 四、取捨：已知不足、沒做完、再給兩天先做什麼

### 已知不足／沒做完

- Pending MFA 與 rate limit 在**記憶體**，重啟即失、無法多實例共享  
- 無 **logout-all**、無 session／裝置列表  
- 無安全的**忘記密碼／MFA 遺失**正式流程（備援碼用盡後只能重建帳號或手動改 DB）  
- 無 Passkeys、無 Email 驗證、無管理後台  
- 無自動載入 `.env`、無正式 migration 工具、無 Playwright E2E  
- README／種子帳號曾落後於功能（強制 MFA）——以本版為準  
- 極簡 UI 僅供 demo，非產品 UX  

### 若再給兩天，優先順序

1. **Logout-all + 列出／撤銷 sessions**（被偷 cookie 時真正救得回來）  
2. **Rate limit／pending MFA 遷到 SQLite 或 Redis**，並補測試（重啟行為可預期）  
3. **備援碼用盡後的高摩擦恢復草案**（例如：冷卻期 + 審計 + 作廢所有 session；不做「一封 email 跳過 MFA」）  
4. 有餘力再：**step-up**（改密碼／重產備援碼再驗 TOTP）、或 **WebAuthn 原型**

不先做華麗 UI 或 SMS：對風險與可維護性的邊際效益較低。

---

## API（摘要）

Base：`http://localhost:3000`  
Cookie：`sid`（`HttpOnly`、`SameSite=Lax`）；DB 存 token 的 SHA-256。

### `POST /signup`

```bash
curl.exe -sS -X POST http://localhost:3000/signup \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"
```

**201** `{ id, email }` · **409** email 已存在

### `POST /login`

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"you@example.com\",\"password\":\"correct-horse-battery-staple\"}"
```

- 尚未開 MFA：**200** `status: MFA_ENROLLMENT_REQUIRED` + `otpauth_uri` + `qr_data_url` + `Set-Cookie: sid`  
- 已開 MFA：**200** `status: MFA_REQUIRED` + `mfa_token`（無 sid）  
- **401** Invalid credentials · **429** Too many attempts  

### `POST /mfa/confirm`（需 sid，且尚未 confirm）

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/confirm \
  -H "Content-Type: application/json" \
  -d "{\"code\":\"123456\"}"
```

**200** `{ mfa_enabled: true, backup_codes: [...] }`

### `POST /mfa/verify`（第 n 次登入）

```bash
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/mfa/verify \
  -H "Content-Type: application/json" \
  -d "{\"mfa_token\":\"PASTE\",\"code\":\"123456\"}"
```

### `GET /me` · `POST /logout`

```bash
curl.exe -sS -c cookies.txt -b cookies.txt http://localhost:3000/me
curl.exe -sS -c cookies.txt -b cookies.txt -X POST http://localhost:3000/logout
```

- Confirm 前 `/me` → **403** `MFA_ENROLLMENT_REQUIRED`  
- 無／失效 session → **401**  
- Logout → **204**

### `POST /mfa/enroll`

可手動重新產生 QR（需 sid、且尚未 `mfa_enabled`）。第 1 次登入通常已自動 enroll。

---

## 已實作控制項（速查）

| 控制 | 作法 |
| --- | --- |
| 密碼 | Argon2id |
| TOTP 種子 | AES-256-GCM |
| 備援碼 | SHA-256、單次、`used_at` |
| Session | Opaque `sid`、DB hash、可撤銷 |
| 強制 MFA | 自動 enroll；Confirm 前擋 `/me` |
| 限流 | 每 email／IP，鎖定時跳過 Argon2 |
| 審計 | login／logout／MFA／backup 事件 |

---

## 專案結構

```
src/app.js           路由與強制 MFA 狀態機
src/users.js         註冊／Argon2id
src/session.js       opaque sid
src/rate-limit.js    限流（可注入 clock）
src/audit.js         audit_logs
src/totp.js          otpauth／驗證
src/crypto-secret.js AES-256-GCM
src/pending-mfa.js   MFA_REQUIRED tokens
src/backup-codes.js  備援碼
src/schema.sql       schema
public/index.html    極簡試玩 UI
scripts/migrate.js   建表
scripts/seed.js      試玩帳號
tests/*.test.mjs     Vitest + Supertest
```
