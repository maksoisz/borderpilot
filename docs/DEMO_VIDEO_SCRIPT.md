# Demo video script (under 5 minutes)

A captioned, silent screen recording made from the real app is included as `BorderPilot_demo_video.mp4` (2 min 22 s). If you record a narrated version, follow this script.

**Setup:** `python -m borderpilot.server`, open http://127.0.0.1:8000, browser zoom 110–125 %, press **Start over**. Record at 1080p with OBS Studio or the system screen recorder. Speak calmly; about 130 words per minute.

| Time | On screen | Say |
|---|---|---|
| 0:00–0:20 | The empty app | “This is BorderPilot, an AI agent that pays study-abroad bills. It runs in a sandbox, so no real money moves. Watch what it does, and what it refuses to do.” |
| 0:20–0:35 | Click **Tuition, UK (genuine)** | “Here is a real-looking tuition invoice: 9,250 pounds to Harbourview University, paid from a student’s zloty account.” |
| 0:35–1:10 | Click **Run the agent**; scroll through steps, payee check, routes, budget | “The agent reads the invoice, checks the payee against the university’s official payment details, gets the exchange rate, compares every route by total cost and worst-case arrival, and shows how long the student’s money lasts. Each step shows its permission level: everything so far is read-only.” |
| 1:10–1:40 | Scroll up to the slip; point at the fingerprint; click **Approve and pay** | “Then it prepares one payment slip. It cannot approve it. The student does. The approval is bound to this exact slip’s fingerprint, works once, and expires in ten minutes. Paid, in the sandbox.” |
| 1:40–2:10 | **Start over**; **“Our bank details changed”**; **Run the agent** | “Now the classic fraud: the same invoice with a new bank account. Blocked. The account is not the university’s official one, and there is no approve button at all.” |
| 2:10–2:40 | **Invoice that orders the AI**; scroll the text to show the injected order; **Run the agent** | “This invoice tells the AI to swap the account and pay without approval. The order is ignored, the extracted account stays official, and the payment is blocked.” |
| 2:40–3:10 | **Start over**; **Look-alike sender**; **Run the agent**; tick the confirmation | “A look-alike sender domain gets Review. The student must first confirm the details through the official website; only then does the button work, and the money can still only go to the official account.” |
| 3:10–3:50 | **Run all attacks**; scroll the table; **Check the log** | “Now we attack it: a hijacked AI, forged and replayed approvals, edited plans, a crash mid-payment, a tampered log. Twenty-four attacks, all stopped. Every step is in a SHA-256 hash-chained audit log.” |
| 3:50–4:20 | Scroll to top | “On 44 test scenarios: 12 of 12 genuine invoices paid correctly, zero of 30 fraud attempts got money, and every result can be reproduced with one command. The AI proposes, code checks, the student signs.” |
