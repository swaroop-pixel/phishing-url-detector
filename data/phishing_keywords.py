"""
Keywords grouped by phishing attack intent, not alphabetically - this keeps
each list conceptually coherent as you extend it (e.g. all KYC-fraud terms
live together, regardless of what gets added later).

Convention: lowercase, single words or short compound tokens (no phrases),
since detector.py matches these against individual URL tokens.
"""

# --- Generic account-related terms --------------------------------------------
ACCOUNT = [
    "account", "profile", "membership", "user", "client", "customer", "portal", 
    "member", "subscriber", "holder", "access", "id", "register", "signup", 
    "settings", "preferences", "dashboard", "workspace"
]

# --- Login/authentication flow terms ------------------------------------------
LOGIN = [
    "login", "signin", "logon", "sign-in", "log-in", "access-denied", "signout", 
    "logout", "entry", "session", "auth", "authorize", "redirect", "gateway", 
    "portal-login", "user-login", "secure-login", "connect", "credentials", "authenticate"
]

# --- Password/credential terms ------------------------------------------------
PASSWORD = [
    "password", "passcode", "pin", "passphrase", "secret", "creds", "credential", 
    "forgot-password", "reset-password", "resetpass", "changepass", "recover-password", 
    "new-password", "keyphrase", "key"
]

# --- Banking-specific terms ----------------------------------------------------
BANKING = [
    "banking", "iban", "swift", "checking", "savings", "creditcard", "debitcard", 
    "account-balance", "transfer", "wire", "routing", "deposit", "withdrawal", 
    "overdraft", "statement", "loan", "mortgage", "vault", "ledger", "online-banking"
]

# --- Payment/billing terms -----------------------------------------------------
PAYMENT = [
    "payment", "billing", "checkout", "pay", "transaction", "invoice", "receipt", 
    "charge", "fee", "cost", "price", "wallet", "merchant", "checkout-flow", 
    "paynow", "purchase", "cardholder", "terminal", "remittance", "funds"
]

# --- Urgency / pressure language ------------------------------------------------
URGENCY = [
    "urgent", "immediately", "suspended", "restricted", "expired", "termination", 
    "warning", "action-required", "alert", "notice", "critical", "important", 
    "disconnection", "block", "blocked", "deactivated", "last-warning", 
    "final-notice", "overdue", "lapse"
]

# --- Delivery / shipping / courier scam terms -----------------------------------
DELIVERY = [
    "delivery", "shipment", "courier", "parcel", "package", "tracking", "post", 
    "shipping", "postage", "dispatch", "transit", "carrier", "warehouse", 
    "address-verification", "missed-delivery", "redelivery", "mailbox", "unclaimed", 
    "customs", "duty"
]

# --- KYC / identity-verification fraud terms ------------------------------------
KYC = [
    "kyc", "identity", "documents", "passport", "licence", "license", "ssn", 
    "verification-photo", "selfie", "compliance", "regulatory", "audit", "onboarding", 
    "upload", "verify-id", "id-card", "national-id"
]

# --- Cryptocurrency-related lure terms -------------------------------------------
CRYPTO = [
    "wallet", "airdrop", "staking", "crypto", "bitcoin", "ethereum", "btc", "eth", 
    "solana", "nft", "seedphrase", "metamask", "trustwallet", "ledger-live", 
    "blockchain", "token", "claim-airdrop", "swap", "mint", "defi"
]

# --- Lottery / prize / reward scam terms -----------------------------------------
LOTTERY = [
    "winner", "prize", "reward", "lottery", "giftcard", "voucher", "bonus", 
    "giveaway", "claim", "congratulations", "won", "draw", "sweepstakes", 
    "freebie", "payout", "jackpot"
]

# --- Invoice / billing document scam terms ---------------------------------------
INVOICE = [
    "invoice", "receipt", "statement", "bill", "purchase-order", "po", "quotation", 
    "estimate", "outstanding", "balance-due", "remittance-advice", "invoice-details", 
    "billing-statement", "receipt-pdf", "payment-advice"
]

# --- Subscription/renewal scam terms ----------------------------------------------
SUBSCRIPTION = [
    "subscription", "renewal", "expired", "autorenew", "plan", "membership-renewal", 
    "cancel", "cancellation", "upgrade", "downgrade", "reactivate", "billing-cycle", 
    "extend", "trial", "payment-failed"
]

# --- Government/tax impersonation terms -------------------------------------------
GOVERNMENT = [
    "tax", "refund", "benefit", "stimulus", "irs", "hmrc", "revenue", "treasury", 
    "government", "gov", "subsidy", "rebate", "tax-return", "audit-notice", 
    "penalty", "court-summons", "fine", "social-security", "allowance", "grant"
]

# --- Employment/recruitment scam terms --------------------------------------------
EMPLOYMENT = [
    "job", "hiring", "recruiter", "offer", "career", "salary", "wage", "contract", 
    "employment", "interview", "application", "resume", "cv", "onboarding-kit", 
    "work-from-home", "remote-job"
]

# --- Refund/chargeback scam terms -------------------------------------------------
REFUND = [
    "refund", "chargeback", "reimbursement", "compensation", "repay", "returned-payment", 
    "overpayment", "refund-request", "credit-note", "claim-refund", "dispute", 
    "settlement", "reclaimed"
]

# --- General security-alert language ----------------------------------------------
SECURITY = [
    "security", "alert", "breach", "compromised", "unauthorized", "suspicious", 
    "activity", "incident", "threat", "malicious", "protection", "firewall", 
    "antivirus", "safe", "secure", "vulnerability", "patch", "mfa-enabled", 
    "security-update", "intrusion"
]

# --- Verification-flow terms -------------------------------------------------------
VERIFY = [
    "verify", "verification", "confirm", "confirmation", "validate", "validation", 
    "approve", "approval", "verify-email", "verify-phone", "status-check", 
    "double-check", "complete-verification", "identity-check"
]

# --- Multi-factor/authentication-specific terms -------------------------------------
AUTHENTICATION = [
    "otp", "2fa", "authenticate", "mfa", "one-time-password", "auth-code", 
    "verification-code", "authenticator", "sms-code", "token-generator", "push-notification", 
    "security-key", "backup-code"
]

# --- Category registry --------------------------------------------------------------
KEYWORDS_BY_CATEGORY = {
    "ACCOUNT": ACCOUNT,
    "LOGIN": LOGIN,
    "PASSWORD": PASSWORD,
    "BANKING": BANKING,
    "PAYMENT": PAYMENT,
    "URGENCY": URGENCY,
    "DELIVERY": DELIVERY,
    "KYC": KYC,
    "CRYPTO": CRYPTO,
    "LOTTERY": LOTTERY,
    "INVOICE": INVOICE,
    "SUBSCRIPTION": SUBSCRIPTION,
    "GOVERNMENT": GOVERNMENT,
    "EMPLOYMENT": EMPLOYMENT,
    "REFUND": REFUND,
    "SECURITY": SECURITY,
    "VERIFY": VERIFY,
    "AUTHENTICATION": AUTHENTICATION,
}

# --- Flattened, deduplicated export for backward-compatible detector.py use ---
PHISHING_KEYWORDS = sorted(set(
    word for category in KEYWORDS_BY_CATEGORY.values() for word in category
))