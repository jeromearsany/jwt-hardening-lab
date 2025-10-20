# 🛡️ Assignment 2: JWT Hardening Submission

**Student Name:** Jerome Arsany Mansour Farah

---

## 🚀 1. How to Set Up and Run the Project

Follow these steps to run the hardened server locally.

1.  **📦 Install Dependencies:**
    ```bash
    npm install
    ```

2.  **🗄️ Initialize the Database:**
    ```bash
    npm run init-db
    ```

3.  **🔑 Create and Populate `.env` File:**
    *   Make a copy of the `env.example` file.
    *   Rename the copy to `.env`.
    *   Open the `.env` file and replace the placeholder secrets with your own securely generated secrets.

4.  **▶️ Run the Hardened Server:**
    ```bash
    npm run start-hardened
    ```
5.  The server will be running at `http://localhost:1234`.

---

## 🔬 2. Steps to Reproduce Demos (Using Postman)

### ⚠️ Vulnerable Demo (for comparison)

1.  Start the vulnerable server: `npm run start-vuln`.
2.  Go to [https://jwt.io/](https://jwt.io/) and switch to the **JWT Encoder**.
3.  Create a forged payload (e.g., `{"username": "attacker", "role": "admin"}`).
4.  Sign it with the known weak secret: `a_very_weak_secret`.
5.  Copy the resulting forged token.
6.  Send a `GET` request in Postman to `http://localhost:1234/profile` with an `Authorization` header set to `Bearer [forged_token]`.
7.  **Result:** The server will accept the token and grant access, demonstrating the vulnerability.

### ✅ Hardened Demo

1.  Start the hardened server: `npm run start-hardened`.
2.  Use the same forged token from the vulnerable demo.
3.  Send the same `GET` request in Postman to `http://localhost:1234/profile`.
4.  **Result:** The server will correctly reject the token with a `403 Forbidden` error, proving the security fix works.

---

## 🌐 3. How to Capture Traffic with Wireshark

1.  Open Wireshark.
2.  Start a capture on the **`Npcap Loopback Adapter`** interface.
3.  While capturing, send a request to a protected endpoint (e.g., `GET /profile`) using Postman with a valid token.
4.  Stop the capture in Wireshark.
5.  Apply the following display filter to find the request:
    ```
    http.request and tcp.port == 1234
    ```
6.  Select the packet and expand the "Hypertext Transfer Protocol" section to view the `Authorization` header containing the plaintext JWT.

---

## 📝 4. Notes and Assumptions

*   The refresh token store is currently in-memory and will be reset on server restart. For production, this would be moved to a persistent database like Redis or SQLite.
*   The project is run over HTTP for the purpose of the Wireshark demonstration. In a real-world scenario, HTTPS would be enforced to encrypt traffic.
