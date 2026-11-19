# VeriClaim - blockchain insurance claims prototype (educational simulation)

## Run (VS Code terminal)
1. Install Python 3.10+. Open this folder in VS Code (File > Open Folder).
2. Terminal:  python -m venv venv
   Windows: venv\Scripts\activate    Mac/Linux: source venv/bin/activate
3. pip install -r requirements.txt
4. python app.py
5. Laptop: http://localhost:5000   Phone: the http://<IP>:5000 URL printed in the terminal
   (phone and laptop on the same hotspot; type http:// explicitly; Windows firewall: allow Python on Private networks)

## Demo PINs
customer 1111 | surveyor 2222 | insurer 3333 | insurer B 4444
Roles are per browser tab, so one browser can hold several roles in separate tabs.

## Demo flow
1. Insurer tab > Tools > Load demo data (fills the dashboard; gives multi-leaf Merkle proofs).
2. Phone: sign in as Customer, file a claim with a camera photo.
3. Surveyor tab: verify the evidence hash, add remarks. Insurer tab: Approve, then Record settlement (simulated).
4. Insurer > Explorer: Alter a transaction / evidence file, watch detection, then Restore.
5. File a "Flight Delay (parametric)" claim: run oracle consensus (agree, conflicting, offline, shared source).
6. Insurer B tab: duplicate check with the same type, date and asset as a customer claim.
7. Consensus Lab (PoW, PoS, PBFT) and Dashboard (bottleneck analysis).

## Limitations
- Single-process simulation, not a distributed network. Role keys are held by the server (Ed25519).
- HMAC fingerprints are keyed hashing, NOT zero-knowledge proofs; anyone holding the shared key can test guesses.
- Oracle agreement does not prove truth; sources must be independent.
- The blockchain proves records were not altered, not that the claim data entered was true.
- Simulation only: no real money, no legal decisions. Fonts fall back to Georgia/Segoe UI offline.
