/**
 * ============================================================
 *  AI Phishing Detection Engine — detector.js
 *  Multi-signal heuristic scoring for URLs, Emails, Messages
 * ============================================================
 */

// ─── SHARED CONSTANTS ────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.gq',
  '.pw', '.cc', '.ws', '.biz', '.info', '.online', '.site',
  '.loan', '.win', '.bid', '.trade', '.racing', '.review',
  '.science', '.work', '.party', '.download', '.stream',
  '.accountant', '.faith', '.cricket', '.date', '.men'
];

const URL_BRAND_SPOOFS = [
  'paypa1', 'paypa|', 'payp4l', 'paypall', 'paypaI',
  'g00gle', 'go0gle', 'googie', 'g0ogle',
  'arnazon', 'amaz0n', 'amazom', 'amzon', 'amazon-',
  'micros0ft', 'microsofl', 'micr0soft',
  'app1e', 'appl3', 'aplle',
  'faceb00k', 'facebok', 'faceboook',
  'netfl1x', 'netfiix',
  'dropb0x', 'dropbox-',
  'linkedln', 'linked-in',
  'twltter', 'tw1tter', 'twitter-',
  'instagrarn', 'instagr4m',
  'bankofamerica-', 'wellsfarg0', 'citibank-',
  'secure-login', 'account-verify', 'signin-',
  '-login', '-signin', '-secure', '-account', '-update', '-verify'
];

const URL_PHISHING_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'logon', 'log-on',
  'verify', 'verification', 'validate', 'validation',
  'update', 'confirm', 'secure', 'security', 'alert',
  'account', 'password', 'passwd', 'credential',
  'banking', 'bank', 'wallet', 'billing', 'payment', 'pay',
  'suspend', 'locked', 'block', 'unusual',
  'free', 'winner', 'prize', 'gift', 'reward',
  'click', 'limited', 'offer', 'deal',
  'invoice', 'receipt', 'order-confirm',
  'reset', 'recover', 'restore', 'reactivate',
  'support', 'helpdesk', 'service-center'
];

const URL_REDIRECT_PATTERNS = [
  '/redirect?', '/go?', '/out?', '/click?', '/track?',
  'url=http', 'url=www', 'link=http', 'goto=', '/forward?',
  'returnurl=', 'return_url=', 'next=http', 'ref=http'
];

const SHORTENED_URL_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl',
  'is.gd', 'buff.ly', 'adf.ly', 'bc.vc', 'tiny.cc',
  'shorturl.at', 'rb.gy', 'cutt.ly', 'clck.ru',
  'short.io', 'soo.gd', 'lnkd.in', 'mcaf.ee', 'su.pr', 'tr.im'
];

// ─── EMAIL CONSTANTS ─────────────────────────────────────────

const EMAIL_URGENCY_KEYWORDS = [
  'act now', 'act immediately', 'urgent', 'immediately',
  'account suspended', 'account locked', 'account disabled',
  'verify now', 'verify immediately', 'confirm now',
  'limited time', 'expires in', 'will expire',
  'final notice', 'last warning', 'last chance',
  'access denied', 'unusual activity', 'suspicious login',
  'your password', 'reset your', 'click here', 'click the link',
  'you have been selected', 'congratulations', 'you won',
  'claim your', 'free gift', 'act fast', 'respond immediately',
  'failure to', 'failure to respond', 'will be terminated',
  'action required', 'response required', 'immediate action'
];

const EMAIL_CREDENTIAL_KEYWORDS = [
  'enter your password', 'confirm your password', 'enter your pin',
  'provide your', 'submit your', 'enter your credit',
  'card number', 'social security', 'ssn', 'date of birth',
  'mother\'s maiden', 'security question', 'secret answer',
  'bank account', 'routing number', 'swift code',
  'update billing', 'payment information', 'verify payment',
  'enter below', 'fill in the form', 'complete the form'
];

const EMAIL_SUSPICIOUS_SENDERS = [
  'noreply@', 'no-reply@', 'donotreply@',
  '@gmail.com', '@yahoo.com', '@hotmail.com', '@outlook.com',
  '@aol.com', '@live.com', '@mail.com', '@icloud.com'
];

const EMAIL_LEGITIMATE_DOMAINS_IMPERSONATED = [
  'paypal', 'amazon', 'google', 'microsoft', 'apple',
  'facebook', 'netflix', 'twitter', 'instagram', 'linkedin',
  'bankofamerica', 'wellsfargo', 'chase', 'citibank',
  'irs', 'fedex', 'ups', 'dhl', 'usps', 'ebay', 'dropbox'
];

const EMAIL_BAD_ATTACHMENT_PATTERNS = [
  '.exe', '.bat', '.cmd', '.vbs', '.js', '.jar',
  '.docm', '.xlsm', '.pptm', '.zip', '.rar', '.7z',
  '.scr', '.pif', '.com', '.lnk', '.msi'
];

const GRAMMAR_RED_FLAGS = [
  /dear (valued|esteemed|respected|beloved) (customer|client|member|user)/i,
  /kindly (click|update|verify|provide|send)/i,
  /your (account|profile) (have been|has been|had been) (suspend|block|lock|disable)/i,
  /we (have|has) notice(d)? (that)? your/i,
  /for (security|safety) (reason|purpose|measure)/i,
  /inconvenience (is|are) (regretted|sorry)/i,
  /do the needful/i,
  /revert back/i,
  /please to (click|update|confirm)/i
];

// ─── MESSAGE CONSTANTS ────────────────────────────────────────

const MESSAGE_SCAM_PATTERNS = [
  /you('ve| have) won/i,
  /congratulations.*prize/i,
  /congratulations.*winner/i,
  /claim your (prize|reward|gift|money)/i,
  /lottery.*win/i,
  /selected.*winner/i,
  /(cash|prize|reward|gift).*claim/i,
  /you('ve| have) been selected/i,
  /\$[\d,]+.*free/i,
  /free (iphone|ipad|samsung|gift card)/i,
  /otp.*do not share/i,
  /do not share.*otp/i,
  /never share.*otp/i,
  /one.time.password/i,
  /verification code.*share/i,
  /your account.*suspended/i,
  /your (bank|credit|debit) account/i,
  /irs.*refund/i,
  /tax refund/i,
  /government.*benefit/i,
  /call.*toll.free/i,
  /call.*immediately/i,
  /click (?:here|the link|below|now)/i,
  /limited.*offer/i,
  /expires (today|now|soon)/i,
  /last chance/i,
  /urgent.*(?:call|click|respond|reply)/i
];

const MESSAGE_IMPERSONATION_PATTERNS = [
  /\b(irs|fbi|cia|fda|cdc|who|interpol)\b/i,
  /\b(bank of america|wells fargo|chase bank|citibank|barclays|hsbc)\b/i,
  /\b(amazon|paypal|apple|google|microsoft|netflix)\b/i,
  /\b(fedex|ups|dhl|usps|royal mail)\b/i,
  /\b(social security|medicare|medicaid)\b/i,
];

const MESSAGE_URGENCY_PATTERNS = [
  /act (now|immediately|fast|quickly)/i,
  /respond (now|immediately|asap)/i,
  /reply (now|immediately|asap)/i,
  /expires? (in \d+ (hour|min|day)|today|now|soon)/i,
  /urgent(ly)?/i,
  /emergency/i,
  /immediately/i,
  /don't (delay|wait|ignore)/i,
  /do not (ignore|delete|discard)/i
];

// ─── URL ANALYZER ─────────────────────────────────────────────

function analyzeURL(rawInput) {
  const signals = [];
  let score = 0;
  const url = rawInput.trim();

  if (!url) return { score: 0, level: 'safe', signals: [] };

  let parsed;
  try {
    parsed = new URL(url.startsWith('http') ? url : 'http://' + url);
  } catch {
    return { score: 20, level: 'suspicious', signals: [{ type: 'warning', text: 'URL could not be parsed — may be malformed or obfuscated.' }] };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl = url.toLowerCase();
  const path = (parsed.pathname + parsed.search).toLowerCase();

  // 1. HTTP (not HTTPS)
  if (parsed.protocol === 'http:') {
    score += 12;
    signals.push({ type: 'danger', text: 'Not using HTTPS — connection is unencrypted and not verified.' });
  }

  // 2. IP address URL
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    score += 22;
    signals.push({ type: 'danger', text: 'URL uses a raw IP address instead of a domain name — classic phishing tactic.' });
  }

  // 3. Suspicious TLD
  const matchedTLD = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));
  if (matchedTLD) {
    score += 15;
    signals.push({ type: 'danger', text: `Suspicious top-level domain "${matchedTLD}" — commonly used in free phishing domains.` });
  }

  // 4. Excessive subdomains (brand buried in subdomain)
  const domainParts = hostname.split('.');
  if (domainParts.length >= 4) {
    score += 14;
    signals.push({ type: 'danger', text: `Excessive subdomains (${domainParts.length} levels) — legitimate brands typically use 1–2 levels.` });
  }

  // 5. Brand spoofing in domain
  const spoofMatch = URL_BRAND_SPOOFS.find(spoof => hostname.includes(spoof));
  if (spoofMatch) {
    score += 25;
    signals.push({ type: 'danger', text: `Lookalike/spoofed brand name detected ("${spoofMatch}") — impersonating a trusted brand.` });
  }

  // 6. @ symbol in URL
  if (url.includes('@')) {
    score += 18;
    signals.push({ type: 'danger', text: 'URL contains "@" symbol — used to deceive by hiding the real destination domain.' });
  }

  // 7. Suspicious phishing keywords in path/query
  const foundKeywords = URL_PHISHING_KEYWORDS.filter(kw => path.includes(kw));
  if (foundKeywords.length > 0) {
    const pts = Math.min(foundKeywords.length * 5, 20);
    score += pts;
    signals.push({ type: 'warning', text: `Phishing-related keywords in URL path: ${foundKeywords.slice(0, 4).map(k => `"${k}"`).join(', ')}.` });
  }

  // 8. URL length
  if (url.length > 100) {
    score += 10;
    signals.push({ type: 'warning', text: `Very long URL (${url.length} chars) — often used to obscure the actual destination.` });
  } else if (url.length > 75) {
    score += 5;
    signals.push({ type: 'warning', text: `Long URL (${url.length} chars) — may be obscuring destination.` });
  }

  // 9. Redirect patterns
  const redirectMatch = URL_REDIRECT_PATTERNS.find(p => fullUrl.includes(p));
  if (redirectMatch) {
    score += 16;
    signals.push({ type: 'danger', text: `URL contains redirect chain pattern ("${redirectMatch}") — may redirect to malicious site.` });
  }

  // 10. Shortened URL
  const shortenedMatch = SHORTENED_URL_DOMAINS.find(d => hostname.includes(d));
  if (shortenedMatch) {
    score += 12;
    signals.push({ type: 'warning', text: `Shortened URL via "${shortenedMatch}" — hides the real destination.` });
  }

  // 11. Data URI
  if (url.startsWith('data:')) {
    score += 25;
    signals.push({ type: 'danger', text: 'Data URI detected — can execute hidden malicious scripts.' });
  }

  // 12. Hexadecimal/percent-encoded obfuscation
  const hexCount = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (hexCount > 5) {
    score += 14;
    signals.push({ type: 'danger', text: `Heavy URL encoding (${hexCount} encoded chars) — often used to obfuscate phishing URLs.` });
  }

  // 13. Hyphen abuse in domain
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    score += 8;
    signals.push({ type: 'warning', text: `Domain contains many hyphens (${hyphenCount}) — common in phishing domains mimicking legitimate sites.` });
  }

  // 14. Double slash in path (odd)
  if (path.includes('//')) {
    score += 6;
    signals.push({ type: 'warning', text: 'Double slashes in URL path — unusual and may indicate obfuscation.' });
  }

  // 15. Known safe domains (positive signal)
  const SAFE_DOMAINS = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'twitter.com', 'linkedin.com', 'github.com', 'youtube.com',
    'wikipedia.org', 'stackoverflow.com', 'reddit.com', 'netflix.com'];
  const isSafe = SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
  if (isSafe && score < 10) {
    signals.push({ type: 'safe', text: `Domain "${hostname}" matches a known trusted site.` });
  }

  score = Math.min(score, 100);
  return { score, level: getRiskLevel(score), signals };
}

// ─── EMAIL ANALYZER ───────────────────────────────────────────

function analyzeEmail({ sender, subject, body }) {
  const signals = [];
  let score = 0;

  const allText = `${sender} ${subject} ${body}`.toLowerCase();
  const bodyLower = body.toLowerCase();
  const subjectLower = subject.toLowerCase();
  const senderLower = sender.toLowerCase();

  // 1. Sender using free email service claiming to be a business
  const isFreeMail = EMAIL_SUSPICIOUS_SENDERS.slice(1).some(d => senderLower.includes(d));
  const impersonatedBrand = EMAIL_LEGITIMATE_DOMAINS_IMPERSONATED.find(brand =>
    allText.includes(brand) && isFreeMail
  );
  if (impersonatedBrand && isFreeMail) {
    score += 25;
    signals.push({ type: 'danger', text: `Sender uses a free email provider (${senderLower.match(/@[a-z.]+/)?.[0] || ''}) while impersonating "${impersonatedBrand}" — classic spoofing.` });
  } else if (isFreeMail && (subject.length > 0 || body.length > 0)) {
    score += 8;
    signals.push({ type: 'warning', text: 'Sender uses a personal/free email domain rather than an official business domain.' });
  }

  // 2. Sender domain mismatch
  const senderEmailMatch = sender.match(/<([^>]+)>/) || sender.match(/([^\s]+@[^\s]+)/);
  const senderEmail = senderEmailMatch ? senderEmailMatch[1] : sender;
  const senderDomain = senderEmail.split('@')[1]?.toLowerCase() || '';
  const brandInSubject = EMAIL_LEGITIMATE_DOMAINS_IMPERSONATED.find(b => subjectLower.includes(b));
  const brandInBody = EMAIL_LEGITIMATE_DOMAINS_IMPERSONATED.find(b => bodyLower.includes(b));
  const mentionedBrand = brandInSubject || brandInBody;
  if (mentionedBrand && senderDomain && !senderDomain.includes(mentionedBrand)) {
    if (!isFreeMail) {
      score += 20;
      signals.push({ type: 'danger', text: `Email claims to be from "${mentionedBrand}" but sender domain is "${senderDomain}" — domain mismatch.` });
    }
  }

  // 3. Urgency keywords
  const foundUrgency = EMAIL_URGENCY_KEYWORDS.filter(kw => allText.includes(kw));
  if (foundUrgency.length >= 3) {
    score += 20;
    signals.push({ type: 'danger', text: `High urgency language detected (${foundUrgency.length} phrases): "${foundUrgency.slice(0, 3).join('", "')}" — creates panic to bypass rational judgment.` });
  } else if (foundUrgency.length > 0) {
    score += foundUrgency.length * 5;
    signals.push({ type: 'warning', text: `Urgency/pressure language detected: "${foundUrgency.slice(0, 2).join('", "')}" — pressures user to act without thinking.` });
  }

  // 4. Credential/sensitive info requests
  const foundCreds = EMAIL_CREDENTIAL_KEYWORDS.filter(kw => allText.includes(kw));
  if (foundCreds.length > 0) {
    score += Math.min(foundCreds.length * 8, 24);
    signals.push({ type: 'danger', text: `Request for sensitive information: "${foundCreds.slice(0, 3).join('", "')}" — legitimate organizations never ask for credentials via email.` });
  }

  // 5. URLs in body
  const urlsInBody = body.match(/https?:\/\/[^\s"<>]+/gi) || [];
  const shortUrls = urlsInBody.filter(u => SHORTENED_URL_DOMAINS.some(d => u.includes(d)));
  if (shortUrls.length > 0) {
    score += 14;
    signals.push({ type: 'danger', text: `Shortened URLs found in body (${shortUrls.length}): ${shortUrls.slice(0, 2).join(', ')} — hides true destination.` });
  }

  // Analyze embedded URLs
  urlsInBody.forEach(u => {
    const urlResult = analyzeURL(u);
    if (urlResult.score > 40) {
      score += 10;
      signals.push({ type: 'danger', text: `Suspicious embedded link detected: "${u.substring(0, 60)}..." scored ${urlResult.score}/100 risk.` });
    }
  });

  // 6. Suspicious attachment mentions
  const foundAttachments = EMAIL_BAD_ATTACHMENT_PATTERNS.filter(ext => allText.includes(ext));
  if (foundAttachments.length > 0) {
    score += 15;
    signals.push({ type: 'danger', text: `Potentially dangerous attachment types mentioned: ${foundAttachments.join(', ')} — may contain malware.` });
  }

  // 7. Grammar red flags
  const grammarMatches = GRAMMAR_RED_FLAGS.filter(re => re.test(allText));
  if (grammarMatches.length > 0) {
    score += grammarMatches.length * 6;
    signals.push({ type: 'warning', text: `Suspicious phrasing / grammar pattern detected (${grammarMatches.length} match${grammarMatches.length > 1 ? 'es' : ''}) — common in phishing templates.` });
  }

  // 8. All-caps subject (panic)
  if (subject.length > 5 && subject === subject.toUpperCase()) {
    score += 8;
    signals.push({ type: 'warning', text: 'Subject line is ALL CAPS — scare tactic to create urgency.' });
  }

  // 9. Mismatched reply-to (heuristic)
  if (senderLower.includes('reply-to:') || senderLower.includes('replyto:')) {
    score += 10;
    signals.push({ type: 'warning', text: 'Custom Reply-To header detected — may divert replies to a different attacker-controlled address.' });
  }

  // 10. Positive: no suspicious signals
  if (score === 0) {
    signals.push({ type: 'safe', text: 'No phishing indicators detected in sender, subject, or body.' });
  }

  score = Math.min(score, 100);
  return { score, level: getRiskLevel(score), signals };
}

// ─── MESSAGE ANALYZER ─────────────────────────────────────────

function analyzeMessage(text) {
  const signals = [];
  let score = 0;
  const lower = text.toLowerCase();

  if (!text.trim()) return { score: 0, level: 'safe', signals: [] };

  // 1. Scam patterns
  const scamMatches = MESSAGE_SCAM_PATTERNS.filter(re => re.test(text));
  if (scamMatches.length > 0) {
    score += Math.min(scamMatches.length * 12, 40);
    signals.push({ type: 'danger', text: `${scamMatches.length} scam pattern${scamMatches.length > 1 ? 's' : ''} detected — prize/lottery/OTP fraud patterns.` });
  }

  // 2. Impersonation of authority
  const impersonated = MESSAGE_IMPERSONATION_PATTERNS.filter(re => re.test(text));
  if (impersonated.length > 0) {
    score += 16;
    signals.push({ type: 'danger', text: 'Impersonation of trusted brand, bank, or government agency detected.' });
  }

  // 3. Urgency patterns
  const urgencyMatches = MESSAGE_URGENCY_PATTERNS.filter(re => re.test(text));
  if (urgencyMatches.length >= 2) {
    score += 15;
    signals.push({ type: 'danger', text: `Strong urgency tactics used (${urgencyMatches.length} patterns) — pressuring immediate action without thinking.` });
  } else if (urgencyMatches.length === 1) {
    score += 8;
    signals.push({ type: 'warning', text: 'Urgency language detected — may be pressuring you to act quickly.' });
  }

  // 4. Shortened URLs
  const urls = text.match(/https?:\/\/[^\s]+/gi) || [];
  const shortened = urls.filter(u => SHORTENED_URL_DOMAINS.some(d => u.includes(d)));
  if (shortened.length > 0) {
    score += 18;
    signals.push({ type: 'danger', text: `Shortened URL(s) in message: ${shortened.join(', ')} — hides the real destination link.` });
  } else if (urls.length > 0) {
    // run URL analysis on found URLs
    urls.forEach(u => {
      const r = analyzeURL(u);
      if (r.score > 35) {
        score += 10;
        signals.push({ type: 'warning', text: `Embedded URL scored ${r.score}/100 risk: "${u.substring(0, 50)}..."` });
      }
    });
  }

  // 5. Phone call request with urgency
  if (/call.*\d{3}|\d{3}.*call/i.test(text) && urgencyMatches.length > 0) {
    score += 12;
    signals.push({ type: 'warning', text: 'Urgently asking you to call a phone number — vishing (voice phishing) tactic.' });
  }

  // 6. Money/financial lure
  if (/\$[\d,]+|\brs\.?\s*[\d,]+|\beur?\s*[\d,]+|\bgbp\b|\blakh\b|\bcrore\b/i.test(text)) {
    score += 10;
    signals.push({ type: 'warning', text: 'Monetary amount mentioned — financial lure commonly used in scam messages.' });
  }

  // 7. Personal info request
  if (/(aadhar|aadhaar|pan card|passport|driving licen[sc]e|account number|credit card|debit card|cvv|otp|pin)/i.test(text)) {
    score += 20;
    signals.push({ type: 'danger', text: 'Request for personal identification or financial data — never share these via message.' });
  }

  if (score === 0 && text.trim().length > 0) {
    signals.push({ type: 'safe', text: 'No phishing or scam patterns detected in this message.' });
  }

  score = Math.min(score, 100);
  return { score, level: getRiskLevel(score), signals };
}

// ─── RISK LEVEL CLASSIFIER ────────────────────────────────────

function getRiskLevel(score) {
  if (score >= 80) return 'phishing';
  if (score >= 56) return 'likely';
  if (score >= 26) return 'suspicious';
  return 'safe';
}

function getRiskMeta(level) {
  const map = {
    safe:       { label: 'Safe',            color: '#22c55e', glow: '#22c55e40', icon: '✅', desc: 'No significant phishing indicators were detected.' },
    suspicious: { label: 'Suspicious',      color: '#eab308', glow: '#eab30840', icon: '⚠️', desc: 'Some warning signs detected. Proceed with caution.' },
    likely:     { label: 'Likely Phishing', color: '#f97316', glow: '#f9731640', icon: '🚨', desc: 'Strong phishing indicators detected. Do not interact.' },
    phishing:   { label: 'Phishing',        color: '#ef4444', glow: '#ef444440', icon: '☠️', desc: 'High-confidence phishing detected. This is very likely malicious.' }
  };
  return map[level] || map.safe;
}
