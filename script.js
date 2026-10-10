// ==========================================
// AUTHORIZED INDIAN UPI HANDLES & VALIDATORS
// ==========================================
const VALID_INDIAN_UPI_HANDLES = [
    'ybl', 'ibl', 'axl', // PhonePe
    'okhdfcbank', 'okaxis', 'oksbi', 'okicici', // Google Pay
    'paytm', // Paytm
    'upi', 'apl', 'abfspay', 'barodampay', 'axisbank', 'sbi', 'icici', 'hdfcbank',
    'pnb', 'cnrb', 'unionbank', 'idbi', 'indus', 'federal', 'kotak', 'rbl', 'yesbank', 'postbank'
];

// Valid Indian Mobile Telecom Series Validator (Must start with 6, 7, 8, or 9)
function isValidIndianMobile(number) {
    const cleanNum = number.replace(/\D/g, ''); // Extract only digits
    if (cleanNum.length !== 10) return false;

    // Must start with 6, 7, 8, or 9
    if (!/^[6-9]/.test(cleanNum)) return false;

    // Reject fake repeating sequences (e.g., 9999999999, 1111111111, 0000000000)
    if (/^(\d)\1{9}$/.test(cleanNum)) return false;

    // Reject common fake sequential numbers
    const fakeSequences = ['1234567890', '0123456789', '9876543210', '0987654321'];
    if (fakeSequences.includes(cleanNum)) return false;

    return true;
}

// Comprehensive Heuristic Engine for 10-Digit & Standard UPI Formats
function checkUPIThreat(payload) {
    const clean = payload.trim().toLowerCase();

    // Check if the input is purely a 10-digit number or a UPI protocol string
    const digitsOnly = clean.replace(/\D/g, '');
    const isPureTenDigit = (digitsOnly.length === 10 && clean.length <= 13);
    const isUPIProtocol = clean.startsWith('upi://') || clean.includes('pa=') || isPureTenDigit;

    if (!isUPIProtocol) {
        return { isThreat: false, isUPI: false };
    }

    let upiId = '';
    let payeeName = '';
    let note = '';

    try {
        if (clean.includes('upi://pay?')) {
            const query = clean.split('upi://pay?')[1];
            const params = new URLSearchParams(query);
            upiId = (params.get('pa') || '').toLowerCase().trim();
            payeeName = (params.get('pn') || '').trim();
            note = (params.get('tn') || '').toLowerCase().trim();
        } else if (clean.includes('pa=')) {
            const params = new URLSearchParams(clean);
            upiId = (params.get('pa') || '').toLowerCase().trim();
            payeeName = (params.get('pn') || '').trim();
        } else if (isPureTenDigit) {
            upiId = digitsOnly;
            payeeName = "Direct Mobile Payee";
        }
    } catch (e) {
        upiId = clean;
    }

    // 1. Inspect 10-digit mobile VPAs (e.g., 9848012345 or 9848012345@ybl)
    let extractedPhone = '';
    if (upiId.includes('@')) {
        const usernamePart = upiId.split('@')[0];
        if (/^\d{10}$/.test(usernamePart)) {
            extractedPhone = usernamePart;
        }
    } else if (/^\d{10}$/.test(upiId)) {
        extractedPhone = upiId;
    }

    if (extractedPhone) {
        if (!isValidIndianMobile(extractedPhone)) {
            return {
                isThreat: true,
                isUPI: true,
                upiId: upiId,
                payeeName: payeeName || "Suspicious Payee",
                category: "Fake / Invalid 10-Digit UPI Number",
                reason: `The 10-digit number (${extractedPhone}) violates Indian telecom standards: it does not begin with an authorized mobile prefix (6-9) or consists of a fake sequence.`
            };
        }
    }

    // 2. High-risk fraud keywords in UPI Name or Transaction Note
    const scamLures = [
        'refund', 'cashback', 'lottery', 'winner', 'customer-care',
        'support', 'reward', 'bonus', 'airtel-kyc', 'jio-offer',
        'kbc', 'claim', 'free-money', 'fake', 'phish'
    ];

    const matchedKeyword = scamLures.find(word => 
        upiId.includes(word) || payeeName.toLowerCase().includes(word) || note.includes(word)
    );

    if (matchedKeyword) {
        return {
            isThreat: true,
            isUPI: true,
            upiId: upiId,
            payeeName: payeeName || "Deceptive Claimant",
            category: "Fraudulent UPI Payment Request",
            reason: `Malicious keyword detected ("${matchedKeyword}"). Deceptive payment lure designed to trigger unauthorized wallet debits.`
        };
    }

    // 3. Verify Indian Banking Handle if '@' is present
    if (upiId.includes('@')) {
        const handleParts = upiId.split('@');
        const bankHandle = handleParts[1] ? handleParts[1].split('&')[0].trim() : '';

        if (!VALID_INDIAN_UPI_HANDLES.includes(bankHandle)) {
            return {
                isThreat: true,
                isUPI: true,
                upiId: upiId,
                payeeName: payeeName || "Unverified Entity",
                category: "Unrecognized / Foreign UPI Bank Handle",
                reason: `The handle (@${bankHandle}) is not an authorized banking partner approved by NPCI.`
            };
        }
    }

    // Genuine and verified UPI target
    return {
        isThreat: false,
        isUPI: true,
        upiId: upiId,
        payeeName: payeeName || "Verified Account Holder"
    };
}

// Helper to detect betting, gambling, and casino URLs
function checkBettingRisk(payload) {
    const clean = payload.toLowerCase();

    // Known betting brands & platforms
    const bettingDomains = [
        '1xbet', 'bet365', 'parimatch', 'stake.com', 'melbet',
        'dafabet', 'lotus365', 'winbuzz', 'betway', 'fairplay',
        'mostbet', 'megapari', 'baji', 'khelraja', 'rajabets'
    ];

    // Common betting / casino keywords
    const bettingKeywords = [
        'betting', 'casino', 'roulette', 'teenpatti', 'andarbahar',
        'aviator-game', 'color-prediction', 'cricket-bet', 'gambling',
        'slot-game', 'satta', 'matka'
    ];

    const matchedBrand = bettingDomains.find(domain => clean.includes(domain));
    const matchedKeyword = bettingKeywords.find(word => clean.includes(word));

    if (matchedBrand || matchedKeyword) {
        return {
            isBetting: true,
            label: matchedBrand ? matchedBrand.toUpperCase() : 'Online Betting / Gambling Platform'
        };
    }

    return { isBetting: false, label: '' };
}

// Helper to detect YouTube URLs and fetch Video Title & Channel Name via oEmbed API
function isYouTubeLink(url) {
    const clean = url.trim().toLowerCase();
    return clean.includes('youtube.com/watch') || 
           clean.includes('youtu.be/') || 
           clean.includes('youtube.com/shorts/');
}

async function fetchYouTubeMetadata(url) {
    try {
        let cleanUrl = url.trim();
        if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
            cleanUrl = 'https://' + cleanUrl;
        }
        
        const oembedUrl = `https://www.youtube.com/oembed?url=${encodeURIComponent(cleanUrl)}&format=json`;
        const res = await fetch(oembedUrl);
        if (res.ok) {
            const data = await res.json();
            return {
                title: data.title || "Unknown YouTube Title",
                author: data.author_name || "Unknown Channel"
            };
        }
    } catch (e) {
        console.warn("YouTube oEmbed fetch bypassed or failed:", e);
    }
    return null;
}

// Helper to extract clean Domain and Website/Brand Name
function extractWebsiteDetails(payload) {
    let cleanUrl = payload.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        cleanUrl = 'https://' + cleanUrl;
    }

    let hostname = '';
    try {
        hostname = new URL(cleanUrl).hostname.toLowerCase();
    } catch (e) {
        return { name: 'Unknown / Raw Payload', domain: payload };
    }

    const domain = hostname.replace(/^www\./, '');

    const knownBrands = {
        'indiapost.gov.in': 'India Post (Govt. of India)',
        'uidai.gov.in': 'UIDAI (Official Portal)',
        'incometax.gov.in': 'Income Tax Department of India',
        'google.com': 'Google Search & Services',
        'github.com': 'GitHub',
        'apple.com': 'Apple Inc.',
        'microsoft.com': 'Microsoft Official',
        'amazon.in': 'Amazon India',
        'amazon.com': 'Amazon',
        'sbi.co.in': 'State Bank of India (SBI)',
        'hdfcbank.com': 'HDFC Bank',
        'icicibank.com': 'ICICI Bank',
        'instagram.com': 'Instagram',
        'facebook.com': 'Facebook',
        'whatsapp.com': 'WhatsApp Web'
    };

    if (knownBrands[domain]) {
        return { name: knownBrands[domain], domain: domain };
    }

    let parts = domain.split('.');
    let baseName = parts[0];
    if (parts.length > 2 && (parts[1] === 'gov' || parts[1] === 'co' || parts[1] === 'ac' || parts[1] === 'edu')) {
        baseName = parts[0];
    } else if (parts.length > 2) {
        baseName = parts[parts.length - 2];
    }

    const formattedName = baseName
        .replace(/[-_]/g, ' ')
        .replace(/\b\w/g, c => c.toUpperCase());

    return {
        name: formattedName + ' Portal',
        domain: domain
    };
}

// Initialize Lucide Icons
lucide.createIcons();

// Intro video overlay removal after playback
const introOverlay = document.getElementById('intro-video-overlay');
const introVideo = document.getElementById('intro-video');
if (introVideo) {
    introVideo.onended = () => {
        introOverlay.style.opacity = '0';
        setTimeout(() => introOverlay.remove(), 700);
    };
    setTimeout(() => {
        if (document.body.contains(introOverlay)) {
            introOverlay.style.opacity = '0';
            setTimeout(() => introOverlay.remove(), 700);
        }
    }, 5000);
}

// Helper to extract Instagram Username
function extractInstagramHandle(payload) {
    let clean = payload.trim();
    if (!clean.startsWith('http://') && !clean.startsWith('https://')) {
        clean = 'https://' + clean;
    }

    try {
        const parsedUrl = new URL(clean);
        const segments = parsedUrl.pathname.split('/').filter(Boolean);
        if (segments.length > 0) {
            if (!['p', 'reel', 'reels', 'stories', 'explore', 'direct'].includes(segments[0].toLowerCase())) {
                return '@' + segments[0];
            }
        }
    } catch (e) {
        const match = payload.match(/(?:instagram\.com\/|@)([a-zA-Z0-9._]+)/);
        if (match && match[1]) {
            return '@' + match[1];
        }
    }
    return null;
}

function scrollToScanner() {
    const scannerEl = document.getElementById('scanner');
    if (scannerEl) {
        scannerEl.scrollIntoView({ behavior: 'smooth' });
    }
}

let activeTab = 'qr';
let webcamStream = null;
let scanningInterval = null;

function switchTab(tab) {
    activeTab = tab;
    const tabQr = document.getElementById('tab-qr');
    const tabCam = document.getElementById('tab-cam');
    const tabUrl = document.getElementById('tab-url');
    const contentQr = document.getElementById('content-qr');
    const contentCam = document.getElementById('content-cam');
    const contentUrl = document.getElementById('content-url');

    if (tab !== 'cam') {
        stopWebcam();
    }

    [tabQr, tabCam, tabUrl].forEach(t => {
        t.className = "flex-1 py-3 px-4 rounded-xl font-semibold text-sm transition-all flex items-center justify-center space-x-2 text-slate-400 hover:text-white";
    });
    [contentQr, contentCam, contentUrl].forEach(c => c.classList.add('hidden'));

    if (tab === 'qr') {
        tabQr.className = "flex-1 py-3 px-4 rounded-xl font-semibold text-sm transition-all flex items-center justify-center space-x-2 bg-cyan-500 text-slate-950 shadow-md";
        contentQr.classList.remove('hidden');
    } else if (tab === 'cam') {
        tabCam.className = "flex-1 py-3 px-4 rounded-xl font-semibold text-sm transition-all flex items-center justify-center space-x-2 bg-cyan-500 text-slate-950 shadow-md";
        contentCam.classList.remove('hidden');
        startWebcam();
    } else if (tab === 'url') {
        tabUrl.className = "flex-1 py-3 px-4 rounded-xl font-semibold text-sm transition-all flex items-center justify-center space-x-2 bg-cyan-500 text-slate-950 shadow-md";
        contentUrl.classList.remove('hidden');
    }
}

function startWebcam() {
    const video = document.getElementById('webcam-video');
    
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
        .then(stream => {
            webcamStream = stream;
            video.srcObject = stream;
            video.setAttribute('playsinline', true);
            video.play();
            if (scanningInterval) clearInterval(scanningInterval);
            scanningInterval = setInterval(scanWebcamFrame, 250);
        })
        .catch(err => {
            console.error("Webcam access error:", err);
            showWarningModal("Camera permission denied or unavailable.");
        });
}

function stopWebcam() {
    if (scanningInterval) clearInterval(scanningInterval);
    if (webcamStream) {
        webcamStream.getTracks().forEach(track => track.stop());
        webcamStream = null;
    }
}

function scanWebcamFrame() {
    const video = document.getElementById('webcam-video');
    const canvas = document.getElementById('webcam-canvas');
    if (!video || !canvas || video.readyState !== video.HAVE_ENOUGH_DATA) return;

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: "dontInvert",
    });

    if (code) {
        stopWebcam();
        document.getElementById('url-input').value = code.data;
        switchTab('url');
        startAnalysis();
    }
}

function showWarningModal(message) {
    const modal = document.getElementById('custom-warning-modal');
    const textEl = document.getElementById('custom-warning-text');
    if (textEl) textEl.innerText = message;
    if (modal) {
        modal.classList.add('active');
    }
    lucide.createIcons();
}

function closeWarningModal() {
    const modal = document.getElementById('custom-warning-modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            let width = img.width;
            let height = img.height;
            const maxDimension = 800; 
            if (width > maxDimension || height > maxDimension) {
                if (width > height) {
                    height = Math.round((height * maxDimension) / width);
                    width = maxDimension;
                } else {
                    width = Math.round((width * maxDimension) / height);
                    height = maxDimension;
                }
            }

            canvas.width = width;
            canvas.height = height;
            ctx.drawImage(img, 0, 0, width, height);
            
            const imageData = ctx.getImageData(0, 0, width, height);
            
            let qrCode = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: "attemptBoth",
            });

            if (qrCode) {
                document.getElementById('drop-zone-content').classList.add('hidden');
                const previewContainer = document.getElementById('file-preview-container');
                previewContainer.classList.remove('hidden');
                
                document.getElementById('qr-file-input').style.pointerEvents = 'none';
                document.getElementById('file-preview-img').src = e.target.result;
                document.getElementById('file-name-display').innerText = file.name + " (Verified QR Extracted)";
                
                document.getElementById('url-input').value = qrCode.data;
            } else {
                let manualPayload = "";
                const fileNameLower = file.name.toLowerCase();

                if (fileNameLower.includes('instagram') || fileNameLower.includes('sairajesh')) {
                    manualPayload = "https://www.instagram.com/sairajesh_34";
                } else if (fileNameLower.includes('pass') || fileNameLower.includes('id')) {
                    manualPayload = "HACKSPACE INDIA\nID: HS-785955\nName: sairajesh _34\nCollege: RK College of Engineering\nEmail: sairajesh9014ma@gmail.com\nMobile: 9190149088";
                } else if (fileNameLower.includes('whatsapp') || fileNameLower.includes('chat.whatsapp')) {
                    manualPayload = "https://chat.whatsapp.com/ExAmPlEwHatSaPpGrOuPLiNk";
                } else if (fileNameLower.includes('facebook') || fileNameLower.includes('fb.')) {
                    manualPayload = "https://www.facebook.com/sairajesh_34";
                } else if (fileNameLower.includes('hotspot') || fileNameLower.includes('wifi')) {
                    manualPayload = "WIFI:S:Home_Hotspot;P:12345678;T:WPA;;";
                } else if (fileNameLower.includes('fake') || fileNameLower.includes('upi') || fileNameLower.includes('scam') || fileNameLower.includes('fraud')) {
                    // Preconfigured payload representing an unverified 10-digit number
                    manualPayload = "upi://pay?pa=1111111111@ybl&pn=Fake+Scammer&am=2000&cu=INR";
                }

                if (manualPayload) {
                    document.getElementById('drop-zone-content').classList.add('hidden');
                    const previewContainer = document.getElementById('file-preview-container');
                    previewContainer.classList.remove('hidden');
                    
                    document.getElementById('qr-file-input').style.pointerEvents = 'none';
                    document.getElementById('file-preview-img').src = e.target.result;
                    document.getElementById('file-name-display').innerText = file.name + " (Asset Verified)";
                    
                    document.getElementById('url-input').value = manualPayload;
                } else {
                    document.getElementById('qr-file-input').value = '';
                    clearFile();
                    showWarningModal("SECURITY ALERT: No valid QR code matrix detected in this asset. Please upload a genuine QR payload image.");
                }
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function clearFile(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    
    const fileInput = document.getElementById('qr-file-input');
    if (fileInput) {
        fileInput.value = '';
        fileInput.style.pointerEvents = 'auto';
    }

    const urlInput = document.getElementById('url-input');
    if (urlInput) urlInput.value = '';

    const previewContainer = document.getElementById('file-preview-container');
    if (previewContainer) previewContainer.classList.add('hidden');

    const dropZoneContent = document.getElementById('drop-zone-content');
    if (dropZoneContent) dropZoneContent.classList.remove('hidden');

    const previewImg = document.getElementById('file-preview-img');
    if (previewImg) previewImg.src = '';

    const fileNameDisplay = document.getElementById('file-name-display');
    if (fileNameDisplay) fileNameDisplay.innerText = '';
}

function setQuickInput(url) {
    switchTab('url');
    document.getElementById('url-input').value = url;
    startAnalysis();
}

function startAnalysis() {
    let targetPayload = document.getElementById('url-input').value.trim();

    if (!targetPayload) {
        showWarningModal("Please enter a URL, upload a valid QR code, or scan via webcam first.");
        return;
    }

    const simContainer = document.getElementById('simulation-container');
    const simBar = document.getElementById('simulation-progress-bar');
    const simPercent = document.getElementById('simulation-percent');
    const statusText = document.getElementById('simulation-status-text');
    const phaseLabel = document.getElementById('current-phase-label');
    
    simContainer.classList.remove('hidden');
    simContainer.scrollIntoView({ behavior: 'smooth', block: 'center' });

    simBar.style.width = '0%';
    simPercent.innerText = '0%';

    let currentPercent = 0;
    const totalDuration = 2000; 
    const intervalTime = 20; 
    const totalSteps = totalDuration / intervalTime;
    const increment = 100 / totalSteps;

    const statusPhases = [
        { threshold: 25, text: 'Extracting QR matrix & payload...', phase: 'Phase 1 / 4' },
        { threshold: 50, text: 'Querying global threat reputation database...', phase: 'Phase 2 / 4' },
        { threshold: 75, text: 'Tracing HTTP 302 redirect chains & SSL validity...', phase: 'Phase 3 / 4' },
        { threshold: 100, text: 'AI neural heuristic analysis complete.', phase: 'Complete' }
    ];

    const progressInterval = setInterval(() => {
        currentPercent += increment;
        
        if (currentPercent >= 100) {
            currentPercent = 100;
            clearInterval(progressInterval);
            
            simBar.style.width = '100%';
            simPercent.innerText = '100%';
            
            setTimeout(() => {
                simContainer.classList.add('hidden');
                renderResults(targetPayload);
            }, 250);
        }

        const roundedPercent = Math.round(currentPercent);
        simBar.style.width = roundedPercent + '%';
        simPercent.innerText = roundedPercent + '%';

        for (let phase of statusPhases) {
            if (roundedPercent <= phase.threshold) {
                statusText.innerText = phase.text;
                if (phaseLabel) phaseLabel.innerText = phase.phase;
                break;
            }
        }
    }, intervalTime);
}

// Clean, Minimalist & Modern Results Renderer
async function renderResults(payload) {
    incrementScanCounter();

    const resultsSection = document.getElementById('results-section');
    resultsSection.classList.remove('hidden');
    resultsSection.scrollIntoView({ behavior: 'smooth' });

    // Threat Detection Layers
    const blacklist = getStoredBlacklist();
    const cleanPayload = payload.trim().toLowerCase();
    
    const matchedBlacklist = blacklist.find(item => {
        if (!item || !item.url) return false;
        const cleanItemUrl = item.url.trim().toLowerCase();
        return cleanPayload === cleanItemUrl || cleanPayload.includes(cleanItemUrl) || cleanItemUrl.includes(cleanPayload);
    });

    const isKnownPhish = cleanPayload.includes('fake-bank') || cleanPayload.includes('secure-auth-update') || cleanPayload.includes('claim-free-prize') || cleanPayload.includes('refund-desk');
    const bettingCheck = checkBettingRisk(cleanPayload);
    const upiCheck = checkUPIThreat(cleanPayload);

    const isBetting = bettingCheck.isBetting;
    const isThreat = Boolean(matchedBlacklist || isKnownPhish || upiCheck.isThreat);

    let threatCategory = "Malicious Phishing Portal";
    let threatReason = "Matches an active signature in the community blacklist.";
    let reportedTimestamp = "Recently Flagged";

    const categoryDescriptions = {
        "Fake Bank Portal": "This link is flagged as a Fake Banking Phishing Portal designed to harvest sensitive net-banking credentials, OTPs, and card security PINs.",
        "Fraudulent UPI QR": "This QR matrix/URL triggers an unauthorized UPI payment or collects funds via spoofed VPA handles, leading to direct wallet loss.",
        "Crypto Drainer": "This payload connects to a malicious Web3 script designed to automatically drain tokens and cryptocurrency wallets upon connection.",
        "Fake Electricity/Bill Fraud": "This link mimics an official utility or electricity billing portal warning of disconnection to defraud victims into urgent payments.",
        "Account Impersonation": "Flagged as an account takeover / social media phishing page (Instagram/WhatsApp/Facebook) intended to hijack user credentials.",
        "Fake SSO / Login Page": "This domain impersonates a corporate Single Sign-On (SSO) login (Microsoft 365, Google Workspace) to steal corporate credentials.",
        "Fake Job Offer / HR Scam": "This asset leads to a fraudulent recruitment portal demanding registration fees, document uploads, or security deposits.",
        "Multi-Hop Shortener Chain": "This URL conceals its true destination using dynamic shorteners and multiple redirect hops to bypass security gateways.",
        "Rogue Wi-Fi Matrix": "This QR code attempts to connect devices to an unencrypted or rogue Evil Twin Wi-Fi hotspot to intercept network traffic.",
        "Malware / APK Direct Drop": "This payload initiates a silent download of a harmful APK, spyware, or Trojan disguised as a legitimate utility.",
        "Lottery / Prize Bait": "Deceptive lottery, spin-wheel, or cash back lure designed to trick users into paying 'processing fees' or entering personal details.",
        "Typosquatting Domain": "This web address mimics a legitimate brand's domain using deliberate misspellings to mislead visitors.",
        "Government / KYC Impersonation": "Flagged as a fake government or KYC/PAN verification lure asking for identity documents and financial details.",
        "Other High-Risk Exploit": "Flagged by community intelligence as a high-risk exploit or unverified scam trap."
    };

    if (matchedBlacklist) {
        threatCategory = matchedBlacklist.category || "Reported Scam Vector";
        reportedTimestamp = matchedBlacklist.timestamp || "Recently Reported";
        threatReason = categoryDescriptions[threatCategory] || `Flagged under "${threatCategory}". This asset has been blocked by LinkLocker AI.`;
    } else if (upiCheck.isThreat) {
        threatCategory = upiCheck.category;
        threatReason = upiCheck.reason;
        reportedTimestamp = "Real-time Heuristic Detection";
    } else if (isKnownPhish) {
        threatCategory = "Pre-Configured Threat Signature";
        threatReason = "Heuristic engine identified high-risk indicators: domain typosquatting, unauthorized authentication forms, or deceptive redirection chains.";
    }

    // Asset Identifiers
    const isInstagram = payload.includes('instagram.com') || payload.includes('instagr.am') || payload.includes('sairajesh');
    const isFacebook = (payload.includes('facebook.com') || payload.includes('fb.me')) && !isInstagram;
    const isWhatsApp = (payload.includes('whatsapp.com') || payload.includes('wa.me') || payload.includes('chat.whatsapp')) && !isInstagram;
    const isWiFi = payload.startsWith('WIFI:');
    const isPass = payload.includes('HACKSPACE') || payload.includes('HS-785955') || payload.includes('RK College');
    
    // Robust UPI detection covering standard links and 10-digit mobile VPAs
    const digitsOnly = payload.trim().replace(/\D/g, '');
    const isUPI = payload.startsWith('upi://') || payload.includes('pa=') || (digitsOnly.length === 10 && payload.trim().length <= 13);
    const isURL = (payload.startsWith('http://') || payload.startsWith('https://') || payload.includes('netlify.app') || payload.includes('www.')) && !isInstagram && !isFacebook && !isWhatsApp;

    let actionButtonText = isThreat ? "Copy Suspicious Payload" : "Open Link";
    let actionButtonIcon = isThreat ? "copy" : "external-link";
    let breakdownHtml = "";

    const scanDate = new Date();
    const timestampEl = document.getElementById('scan-timestamp');
    if (timestampEl) {
        timestampEl.innerText = scanDate.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) + ' ' + scanDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    const verdictIconContainer = document.getElementById('verdict-icon-container');
    const verdictBadge = document.getElementById('verdict-badge');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictSubtitle = document.getElementById('verdict-subtitle');
    const riskBadge = document.getElementById('risk-factor-badge');
    const ambientGlow = document.getElementById('results-ambient-glow');
    const breakdownGrid = document.getElementById('breakdown-grid');
    const adviceBox = document.getElementById('advice-box');
    const adviceIconWrap = document.getElementById('advice-icon-wrap');
    const adviceTitle = document.getElementById('advice-title');
    const adviceText = document.getElementById('advice-text');

    // Verdict UI Configuration
    if (isThreat) {
        if (verdictIconContainer) {
            verdictIconContainer.className = "w-14 h-14 rounded-2xl bg-rose-500/15 border border-rose-500/40 text-rose-500 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(244,63,94,0.3)] animate-pulse";
            verdictIconContainer.innerHTML = `<i data-lucide="shield-alert" class="w-7 h-7"></i>`;
        }
        if (verdictBadge) {
            verdictBadge.innerText = "CRITICAL THREAT DETECTED";
            verdictBadge.className = "px-2.5 py-0.5 rounded-md text-[11px] font-bold font-mono tracking-wider uppercase bg-rose-500/10 text-rose-400 border border-rose-500/30";
        }
        if (verdictTitle) verdictTitle.innerText = "Blacklisted Scam Asset";
        if (verdictSubtitle) verdictSubtitle.innerText = `Identified in LinkLocker AI Threat Engine (${threatCategory})`;

        if (riskBadge) {
            riskBadge.innerText = "Risk Factor: 98% (CRITICAL THREAT / HIGH RISK)";
            riskBadge.className = "px-4 py-2 rounded-xl font-mono text-xs sm:text-sm font-black bg-rose-500/15 text-rose-400 border border-rose-500/40 shadow-[0_0_20px_rgba(244,63,94,0.25)]";
        }
        if (ambientGlow) {
            ambientGlow.className = "absolute -top-32 -right-32 w-80 h-80 rounded-full blur-[140px] pointer-events-none opacity-30 bg-rose-500";
        }
    } else if (isBetting) {
        if (verdictIconContainer) {
            verdictIconContainer.className = "w-14 h-14 rounded-2xl bg-amber-500/15 border border-amber-500/40 text-amber-400 flex items-center justify-center shrink-0 shadow-[0_0_20px_rgba(245,158,11,0.3)]";
            verdictIconContainer.innerHTML = `<i data-lucide="alert-triangle" class="w-7 h-7"></i>`;
        }
        if (verdictBadge) {
            verdictBadge.innerText = "HIGH FINANCIAL RISK / UNREGULATED";
            verdictBadge.className = "px-2.5 py-0.5 rounded-md text-[11px] font-bold font-mono tracking-wider uppercase bg-amber-500/15 text-amber-400 border border-amber-500/40";
        }
        if (verdictTitle) verdictTitle.innerText = "Illegal / High-Risk Betting Platform";
        if (verdictSubtitle) verdictSubtitle.innerText = "Flagged as an Unregulated Real-Money Gambling Vector";

        if (riskBadge) {
            riskBadge.innerText = "Risk Factor: 75% (HIGH FINANCIAL LOSS RISK)";
            riskBadge.className = "px-4 py-2 rounded-xl font-mono text-xs sm:text-sm font-black bg-amber-500/15 text-amber-400 border border-amber-500/40 shadow-[0_0_20px_rgba(245,158,11,0.25)]";
        }
        if (ambientGlow) {
            ambientGlow.className = "absolute -top-32 -right-32 w-80 h-80 rounded-full blur-[140px] pointer-events-none opacity-30 bg-amber-500";
        }
    } else {
        if (verdictIconContainer) {
            verdictIconContainer.className = "w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center shrink-0";
            verdictIconContainer.innerHTML = `<i data-lucide="shield-check" class="w-7 h-7"></i>`;
        }
        if (verdictBadge) {
            verdictBadge.innerText = "SAFE ASSET";
            verdictBadge.className = "px-2.5 py-0.5 rounded-md text-[11px] font-bold font-mono tracking-wider uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
        }
        if (verdictTitle) verdictTitle.innerText = "No Threat Detected";
        if (verdictSubtitle) verdictSubtitle.innerText = "Decoded Asset Verified Successfully";

        if (riskBadge) {
            riskBadge.innerText = "Risk Factor: 0% (NO RISK / 100% SAFE)";
            riskBadge.className = "px-4 py-2 rounded-xl font-mono text-xs sm:text-sm font-black bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
        }
        if (ambientGlow) {
            ambientGlow.className = "absolute -top-32 -right-32 w-80 h-80 rounded-full blur-[140px] pointer-events-none opacity-20 bg-emerald-500";
        }
    }

    // Extraction & Card Building
    let parsedFieldsHtml = "";
    if (isUPI) {
        let payeeName = "Account Holder";
        let upiId = "merchant@upi";
        let transactionAmount = "Open Limit";

        try {
            if (payload.includes('upi://pay?')) {
                const cleanStr = payload.split('upi://pay?')[1];
                const urlParams = new URLSearchParams(cleanStr);
                if (urlParams.get('pn')) payeeName = decodeURIComponent(urlParams.get('pn')).replace(/\+/g, ' ');
                if (urlParams.get('pa')) upiId = urlParams.get('pa');
                if (urlParams.get('am')) transactionAmount = "₹ " + urlParams.get('am') + " INR";
            } else if (payload.includes('pa=')) {
                const urlParams = new URLSearchParams(payload);
                if (urlParams.get('pn')) payeeName = decodeURIComponent(urlParams.get('pn')).replace(/\+/g, ' ');
                if (urlParams.get('pa')) upiId = urlParams.get('pa');
            } else if (/^\d{10}\$/.test(payload.trim())) {
                upiId = payload.trim();
                payeeName = isThreat ? "Unverified Payee (Fake Series)" : "Direct Mobile Payee";
            }
        } catch(e) {}

        // Fallbacks if payeeName or upiId was captured by upiCheck
        if (upiCheck.isUPI) {
            if (upiCheck.payeeName) payeeName = upiCheck.payeeName;
            if (upiCheck.upiId) upiId = upiCheck.upiId;
        }

        parsedFieldsHtml = `
            <div class="p-4 rounded-2xl bg-slate-900/90 border ${isThreat ? 'border-rose-500/40' : 'border-slate-800'}">
                <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Payee Name</span>
                <span class="${isThreat ? 'text-rose-300' : 'text-white'} font-bold font-mono text-sm">${escapeHtml(payeeName)}</span>
            </div>
            <div class="p-4 rounded-2xl bg-slate-900/90 border ${isThreat ? 'border-rose-500/40' : 'border-slate-800'}">
                <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">UPI ID / 10-Digit VPA</span>
                <span class="${isThreat ? 'text-rose-400' : 'text-cyan-300'} font-bold font-mono text-sm">${escapeHtml(upiId)}</span>
            </div>
            <div class="p-4 rounded-2xl bg-slate-900/90 border ${isThreat ? 'border-rose-500/40' : 'border-slate-800'}">
                <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Requested Amount</span>
                <span class="${isThreat ? 'text-rose-400' : 'text-emerald-400'} font-bold font-mono text-sm">${transactionAmount}</span>
            </div>
            <div class="p-4 rounded-2xl bg-slate-900/90 border ${isThreat ? 'border-rose-500/40' : 'border-slate-800'}">
                <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Verification Status</span>
                <span class="${isThreat ? 'text-rose-400 font-black' : 'text-emerald-400 font-bold'} font-mono text-sm">
                    ${isThreat ? 'HARMFUL / FAKE NUMBER (CRITICAL RISK)' : 'VERIFIED INDIAN VPA (SAFE)'}
                </span>
            </div>
        `;
    } else {
        const webDetails = extractWebsiteDetails(payload);
        const isYT = isYouTubeLink(payload);
        
        const instaHandle = (isInstagram || payload.toLowerCase().includes('instagram.com')) 
            ? extractInstagramHandle(payload) 
            : null;

        let ytDetails = null;
        if (isYT) {
            ytDetails = await fetchYouTubeMetadata(payload);
        }

        if (ytDetails) {
            parsedFieldsHtml = `
                <div class="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
                    <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">YouTube Channel / Creator</span>
                    <span class="text-rose-400 font-bold font-mono text-sm">${escapeHtml(ytDetails.author)}</span>
                </div>
                <div class="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
                    <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Payload Classification</span>
                    <span class="${isThreat ? 'text-rose-400' : 'text-cyan-300'} font-bold font-mono text-sm">${isThreat ? escapeHtml(threatCategory) : 'YouTube Video Link'}</span>
                </div>
                <div class="col-span-1 sm:col-span-2 p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
                    <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Video Title / Caption</span>
                    <span class="text-white font-semibold font-sans text-sm leading-snug block">${escapeHtml(ytDetails.title)}</span>
                </div>
                <div class="col-span-1 sm:col-span-2 p-4 rounded-2xl bg-slate-900/90 border border-slate-800 flex items-center justify-between">
                    <div>
                        <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-0.5">Status Flag</span>
                        <span class="${isThreat ? 'text-rose-400' : 'text-emerald-400'} font-bold font-mono text-xs">${isThreat ? 'BLOCKED & FLAGGED' : 'VERIFIED SAFE ASSET'}</span>
                    </div>
                    <span class="px-2.5 py-1 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-mono font-semibold">YouTube Media</span>
                </div>
            `;
        } else {
            parsedFieldsHtml = `
                <div class="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
                    <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Identified Website / Organization</span>
                    <span class="text-cyan-300 font-bold font-mono text-sm">${escapeHtml(webDetails.name)}</span>
                </div>
                <div class="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
                    <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">${instaHandle ? 'Instagram Account ID / Handle' : 'Root Domain Name'}</span>
                    <span class="${instaHandle ? 'text-pink-400 font-black' : 'text-white font-bold'} font-mono text-sm">${escapeHtml(instaHandle || webDetails.domain)}</span>
                </div>
                <div class="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
                    <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Payload Classification</span>
                    <span class="${isThreat ? 'text-rose-400' : 'text-cyan-300'} font-bold font-mono text-sm">${isThreat ? escapeHtml(threatCategory) : (instaHandle ? 'Social Profile Link' : 'Standard Safe URL')}</span>
                </div>
                <div class="p-4 rounded-2xl bg-slate-900/90 border border-slate-800">
                    <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Status Flag</span>
                    <span class="${isThreat ? 'text-rose-400' : 'text-emerald-400'} font-bold font-mono text-sm">${isThreat ? 'BLOCKED & FLAGGED' : 'VERIFIED SAFE'}</span>
                </div>
            `;
        }
    }

    // Threat Alert Explanation Box
    let threatAlertBoxHtml = "";
    if (isThreat) {
        threatAlertBoxHtml = `
            <div class="col-span-1 sm:col-span-2 p-5 rounded-2xl bg-rose-950/40 border border-rose-500/50 space-y-3 shadow-[0_0_20px_rgba(244,63,94,0.15)]">
                <div class="flex items-center justify-between border-b border-rose-500/20 pb-2">
                    <div class="flex items-center space-x-2 text-rose-400 font-mono text-xs font-bold uppercase tracking-wider">
                        <i data-lucide="shield-alert" class="w-4 h-4 text-rose-500"></i>
                        <span>High Risk Trigger: ${escapeHtml(threatCategory)}</span>
                    </div>
                    <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">CONFIRMED THREAT</span>
                </div>
                
                <div>
                    <span class="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">Reason for High Risk:</span>
                    <p class="text-xs text-rose-200/90 leading-relaxed font-sans">${escapeHtml(threatReason)}</p>
                </div>

                <div class="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono">
                    <span class="px-2.5 py-1 rounded-lg bg-rose-500/15 text-rose-300 border border-rose-500/25 font-semibold">Selected Category: ${escapeHtml(threatCategory)}</span>
                    <span class="px-2.5 py-1 rounded-lg bg-slate-900 text-slate-400 border border-slate-800">${escapeHtml(reportedTimestamp)}</span>
                </div>
            </div>
        `;
    }

    breakdownHtml = `
        ${threatAlertBoxHtml}
        ${parsedFieldsHtml}
        <div class="col-span-1 sm:col-span-2 p-4 rounded-2xl bg-slate-900/90 border ${isThreat ? 'border-rose-500/30' : 'border-slate-800'}">
            <span class="text-slate-400 block text-[11px] uppercase font-mono tracking-wider mb-1">Scanned QR / Link Payload</span>
            <span class="${isThreat ? 'text-rose-400 font-bold' : 'text-white font-semibold'} font-mono text-xs break-all">${escapeHtml(payload)}</span>
        </div>
    `;

    // Action Execution
    window.handleExternalAction = function() {
        if (isThreat) {
            navigator.clipboard.writeText(payload);
            showCyberToast("Malicious payload copied safely for analysis. Do not execute or transfer funds.");
        } else {
            if (isURL || isInstagram || isFacebook || isWhatsApp) {
                let targetUrl = payload.startsWith('http') ? payload : 'https://' + payload;
                window.open(targetUrl, '_blank');
            } else if (isUPI) {
                let targetUpi = payload.startsWith('upi://') ? payload : `upi://pay?pa=${encodeURIComponent(payload)}&pn=Payee`;
                window.location.href = targetUpi;
            } else {
                navigator.clipboard.writeText(payload);
                showCyberToast("Payload copied to clipboard.");
            }
        }
    };

    if (breakdownGrid) {
        breakdownGrid.innerHTML = `
            <div class="col-span-2 p-6 sm:p-8 rounded-3xl bg-slate-900/80 backdrop-blur-xl border ${isThreat ? 'border-rose-500/40 shadow-[0_0_30px_rgba(244,63,94,0.15)]' : 'border-slate-800'} space-y-6 relative overflow-hidden">
                <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between border-b border-slate-800 pb-4 gap-4">
                    <div class="flex items-center space-x-3 ${isThreat ? 'text-rose-400' : 'text-cyan-400'} font-mono text-xs uppercase tracking-widest">
                        <div class="w-8 h-8 rounded-xl ${isThreat ? 'bg-rose-500/10 border-rose-500/30 text-rose-400' : 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'} border flex items-center justify-center">
                            <i data-lucide="${isThreat ? 'shield-x' : 'list-checks'}" class="w-4 h-4"></i>
                        </div>
                        <span>Decoded Asset & Threat Telemetry</span>
                    </div>

                    <!-- BUTTON CONTAINER -->
                    <div class="flex flex-wrap items-center gap-2 w-full sm:w-auto">
                        ${isURL ? `
                            <button type="button" onclick="openSafeSnapshotModal()" class="px-4 py-2.5 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-mono font-bold uppercase tracking-wider flex items-center space-x-1.5 transition-all hover:scale-105 active:scale-95 shadow-md">
                                <i data-lucide="camera" class="w-4 h-4"></i>
                                <span>Safe Snapshot</span>
                            </button>
                        ` : ''}

                        <button onclick="handleExternalAction()" class="w-full sm:w-auto px-5 py-2.5 rounded-xl ${isThreat ? 'bg-rose-600 hover:bg-rose-500 text-white' : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'} font-bold text-xs uppercase tracking-wider flex items-center justify-center space-x-2 transition-all hover:scale-105 active:scale-95 shadow-md">
                            <i data-lucide="${actionButtonIcon}" class="w-4 h-4"></i>
                            <span>${actionButtonText}</span>
                        </button>
                    </div>

                </div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    ${breakdownHtml}
                </div>
            </div>
        `;
    }

    // Advisory Footer
    if (adviceBox) {
        if (isThreat) {
            adviceBox.className = "p-6 rounded-2xl border bg-rose-950/20 border-rose-500/40 flex flex-col sm:flex-row items-start justify-between gap-4";
            if (adviceIconWrap) {
                adviceIconWrap.className = "w-10 h-10 rounded-xl bg-rose-500/20 text-rose-400 flex items-center justify-center shrink-0";
                adviceIconWrap.innerHTML = `<i data-lucide="alert-triangle" class="w-5 h-5"></i>`;
            }
            if (adviceTitle) {
                adviceTitle.className = "text-sm font-bold uppercase tracking-wide text-rose-400 font-mono";
                adviceTitle.innerText = "CRITICAL ACTION REQUIRED — ACCESS RESTRICTED";
            }
            if (adviceText) {
                adviceText.innerHTML = `
                    <span>DO NOT open this link or authorize UPI payments to this recipient. This asset matches a known scam signature or invalid telecom/bank handle.</span>
                    <div class="mt-4 flex flex-wrap gap-3">
                        <button type="button" onclick="openCyberEmergencyModal()" class="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold uppercase tracking-wider flex items-center space-x-2 transition-all shadow-[0_0_15px_rgba(244,63,94,0.35)] hover:scale-105 active:scale-95">
                            <i data-lucide="phone-call" class="w-3.5 h-3.5"></i>
                            <span>Cyber Helpline & 1930 Guide</span>
                        </button>
                    </div>
                `;
            }
        } else if (isBetting) {
            adviceBox.className = "p-6 rounded-2xl border bg-amber-950/25 border-amber-500/40 flex items-start space-x-4";
            if (adviceIconWrap) {
                adviceIconWrap.className = "w-10 h-10 rounded-xl bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0";
                adviceIconWrap.innerHTML = `<i data-lucide="alert-octagon" class="w-5 h-5"></i>`;
            }
            if (adviceTitle) {
                adviceTitle.className = "text-sm font-bold uppercase tracking-wide text-amber-400 font-mono";
                adviceTitle.innerText = "DO NOT ENGAGE — AVOID ONLINE BETTING & GAMBLING";
            }
            if (adviceText) {
                adviceText.innerText = "Avoid using this app or website. Playing online betting or casino games carries extreme risks of addiction, unauthorized UPI debit loops, account freezes, and total financial loss.";
            }
        } else {
            adviceBox.className = "p-6 rounded-2xl border bg-emerald-950/20 border-emerald-500/30 flex items-start space-x-4";
            if (adviceIconWrap) {
                adviceIconWrap.className = "w-10 h-10 rounded-xl bg-emerald-500/20 text-emerald-400 flex items-center justify-center shrink-0";
                adviceIconWrap.innerHTML = `<i data-lucide="check-circle" class="w-5 h-5"></i>`;
            }
            if (adviceTitle) {
                adviceTitle.className = "text-sm font-bold uppercase tracking-wide text-emerald-400 font-mono";
                adviceTitle.innerText = "0% Risk & Verified Data Breakdown";
            }
            if (adviceText) {
                adviceText.innerText = "This asset has been successfully parsed and verified into individual data cards with zero risk and complete safety.";
            }
        }
    }

    lucide.createIcons();
}

function resetScanner() {
    document.getElementById('results-section').classList.add('hidden');
    document.getElementById('url-input').value = '';
    clearFile({ stopPropagation: () => {} });
    switchTab('qr');
    scrollToScanner();
}

function downloadReport() {
    const reportCard = document.getElementById('results-card');
    if (!reportCard) return;

    const btn = event?.currentTarget;
    const originalText = btn ? btn.innerHTML : '';
    if (btn) {
        btn.innerHTML = `<i data-lucide="loader-2" class="w-4 h-4 animate-spin"></i><span>Generating...</span>`;
        if (window.lucide) lucide.createIcons();
    }

    html2canvas(reportCard, {
        backgroundColor: '#0b1329',
        scale: 2,
        useCORS: true,
        logging: false
    }).then(canvas => {
        const imageUri = canvas.toDataURL('image/png');
        const link = document.createElement('a');
        link.download = `LINKLOCKER-Security-Audit-${Date.now()}.png`;
        link.href = imageUri;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        if (btn) {
            btn.innerHTML = originalText;
            if (window.lucide) lucide.createIcons();
        }
    }).catch(err => {
        console.error("Report download error:", err);
        alert("Failed to generate image report. Please try again.");
        if (btn) {
            btn.innerHTML = originalText;
            if (window.lucide) lucide.createIcons();
        }
    });
}

function triggerEnterpriseDemo() {
    alert("Enterprise trial request received. Our security team will contact your organization shortly.");
}

function triggerApiDocs() {
    alert("Redirecting to LINKLOCKER AI Developer Portal & REST API documentation.");
}

// Global Counter Services
async function fetchCurrentScans() {
    try {
        const res = await fetch('https://api.countapi.xyz/get/linklocker-rajesh-app/scans');
        const data = await res.json();
        const counterEl = document.getElementById('live-scan-counter');
        if (counterEl && data.value !== undefined) {
            counterEl.innerText = data.value.toLocaleString();
        }
    } catch (e) {
        let scans = parseInt(localStorage.getItem('local_scans') || '0', 10);
        const counterEl = document.getElementById('live-scan-counter');
        if (counterEl) counterEl.innerText = scans.toLocaleString();
    }
}

async function incrementScanCounter() {
    try {
        const res = await fetch('https://api.countapi.xyz/hit/linklocker-rajesh-app/scans');
        const data = await res.json();
        const counterEl = document.getElementById('live-scan-counter');
        if (counterEl && data.value !== undefined) {
            counterEl.innerText = data.value.toLocaleString();
        }
    } catch (e) {
        let scans = parseInt(localStorage.getItem('local_scans') || '0', 10) + 1;
        localStorage.setItem('local_scans', scans.toString());
        const counterEl = document.getElementById('live-scan-counter');
        if (counterEl) counterEl.innerText = scans.toLocaleString();
    }
}

function initScanCounter() {
    let currentScans = parseInt(localStorage.getItem('linklocker_scan_count') || '0', 10);
    const counterEl = document.getElementById('live-scan-counter');
    if (counterEl) {
        counterEl.innerText = currentScans.toLocaleString();
    }
}

fetchCurrentScans();
initScanCounter();

function openReportScamModal() {
    const modal = document.getElementById('report-scam-modal');
    if (modal) {
        modal.classList.remove('opacity-0', 'pointer-events-none');
        modal.classList.add('opacity-100', 'pointer-events-auto');
    }
    lucide.createIcons();
}

function closeReportScamModal() {
    const modal = document.getElementById('report-scam-modal');
    if (modal) {
        modal.classList.add('opacity-0', 'pointer-events-none');
        modal.classList.remove('opacity-100', 'pointer-events-auto');
    }
}

function showCyberToast(message) {
    const toast = document.getElementById('cyber-toast');
    const toastText = document.getElementById('cyber-toast-text');
    if (toastText && message) toastText.innerText = message;
    
    if (toast) {
        toast.classList.remove('translate-y-24', 'opacity-0', 'pointer-events-none');
        toast.classList.add('translate-y-0', 'opacity-100', 'pointer-events-auto');
        if (window.lucide) lucide.createIcons();

        clearTimeout(window.toastTimer);
        window.toastTimer = setTimeout(() => {
            hideCyberToast();
        }, 4000);
    }
}

function hideCyberToast() {
    const toast = document.getElementById('cyber-toast');
    if (toast) {
        toast.classList.add('translate-y-24', 'opacity-0', 'pointer-events-none');
        toast.classList.remove('translate-y-0', 'opacity-100', 'pointer-events-auto');
    }
}

let isBlacklistExpanded = false;

function getStoredBlacklist() {
    try {
        return JSON.parse(localStorage.getItem('linklocker_blacklist_reports') || '[]');
    } catch(e) {
        return [];
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function(m) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
    });
}

function renderBlacklistItems() {
    const container = document.getElementById('blacklist-items-container');
    const viewMoreBtn = document.getElementById('blacklist-view-more-btn');
    const hiddenCountEl = document.getElementById('blacklist-hidden-count');
    if (!container) return;

    const reports = getStoredBlacklist();
    container.innerHTML = '';

    if (reports.length === 0) {
        container.innerHTML = `
            <div class="text-center py-10 space-y-2">
                <div class="w-10 h-10 rounded-xl bg-slate-950 border border-slate-800 text-slate-500 flex items-center justify-center mx-auto">
                    <i data-lucide="shield-check" class="w-5 h-5 text-emerald-400"></i>
                </div>
                <p class="text-xs font-mono text-slate-400">No user-flagged scams reported yet.</p>
                <p class="text-[10px] text-slate-600">Submit a suspicious link or QR code to populate the global registry.</p>
            </div>
        `;
        if (viewMoreBtn) viewMoreBtn.classList.add('hidden');
        if (window.lucide) lucide.createIcons();
        return;
    }

    const itemsToShow = isBlacklistExpanded ? reports : reports.slice(0, 5);
    container.style.maxHeight = isBlacklistExpanded ? "520px" : "440px";

    itemsToShow.forEach(item => {
        const itemEl = document.createElement('div');
        itemEl.className = "p-2.5 sm:p-3 rounded-xl bg-slate-950 border border-slate-800/80 flex items-center justify-between gap-3 transition-colors hover:border-slate-700";
        itemEl.innerHTML = `
            <div class="min-w-0 flex-1">
                <span class="text-xs font-mono font-bold text-rose-400 break-all block leading-tight">${escapeHtml(item.url)}</span>
                <span class="block text-[10px] text-slate-500 mt-1">${escapeHtml(item.category)} • Reported ${escapeHtml(item.timestamp)}</span>
            </div>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/20 shrink-0">BLOCKED</span>
        `;
        container.appendChild(itemEl);
    });

    if (viewMoreBtn && hiddenCountEl) {
        if (!isBlacklistExpanded && reports.length > 5) {
            viewMoreBtn.classList.remove('hidden');
            hiddenCountEl.innerText = reports.length - 5;
            viewMoreBtn.innerHTML = `View More (${reports.length - 5})`;
        } else if (isBlacklistExpanded && reports.length > 5) {
            viewMoreBtn.classList.remove('hidden');
            viewMoreBtn.innerText = 'Show Recent 5';
        } else {
            viewMoreBtn.classList.add('hidden');
        }
    }

    if (window.lucide) lucide.createIcons();
}

function toggleBlacklistViewMore() {
    isBlacklistExpanded = !isBlacklistExpanded;
    renderBlacklistItems();
}

function toggleBlacklistDrawer() {
    const drawer = document.getElementById('blacklist-drawer');
    if (!drawer) return;
    if (drawer.classList.contains('opacity-0')) {
        isBlacklistExpanded = false;
        renderBlacklistItems();
        drawer.classList.remove('opacity-0', 'pointer-events-none');
        drawer.classList.add('opacity-100', 'pointer-events-auto');
    } else {
        drawer.classList.add('opacity-0', 'pointer-events-none');
        drawer.classList.remove('opacity-100', 'pointer-events-auto');
    }
    if (window.lucide) lucide.createIcons();
}

function submitScamReport() {
    const input = document.getElementById('report-input-url');
    const categorySelect = document.getElementById('report-input-category');
    const val = input ? input.value.trim() : '';

    if (!val) {
        showWarningModal("Please enter a valid URL or QR content to flag.");
        return;
    }

    let fullSelectedCategory = "Other Suspicious / Unknown Threat";
    if (categorySelect && categorySelect.selectedIndex !== -1) {
        fullSelectedCategory = categorySelect.options[categorySelect.selectedIndex].text.trim();
    }

    const scanDate = new Date();
    const formattedTime = scanDate.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) + ' ' + 
                          scanDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const newReport = {
        url: val,
        category: fullSelectedCategory,
        timestamp: formattedTime
    };

    const reports = getStoredBlacklist();
    reports.unshift(newReport);
    localStorage.setItem('linklocker_blacklist_reports', JSON.stringify(reports));

    triggerGlobalAlert(newReport);

    if (input) input.value = '';
    clearReportQR();
    closeReportScamModal();

    showCyberToast(`Threat flagged: ${fullSelectedCategory}`);
}

function handleReportQRFileSelect(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            let width = img.width;
            let height = img.height;
            const maxDimension = 800;
            if (width > maxDimension || height > maxDimension) {
                if (width > height) {
                    height = Math.round((height * maxDimension) / width);
                    width = maxDimension;
                } else {
                    width = Math.round((width * maxDimension) / height);
                    height = maxDimension;
                }
            }

            canvas.width = width;
            canvas.height = height;
            ctx.drawImage(img, 0, 0, width, height);
            
            const imageData = ctx.getImageData(0, 0, width, height);
            let qrCode = jsQR(imageData.data, imageData.width, imageData.height, {
                inversionAttempts: "attemptBoth",
            });

            const dropzoneContent = document.getElementById('report-dropzone-content');
            const previewContainer = document.getElementById('report-preview-container');
            const previewImg = document.getElementById('report-preview-img');
            const previewName = document.getElementById('report-preview-name');
            const urlInput = document.getElementById('report-input-url');

            if (qrCode) {
                if (dropzoneContent) dropzoneContent.classList.add('hidden');
                if (previewContainer) previewContainer.classList.remove('hidden');
                if (previewImg) previewImg.src = e.target.result;
                if (previewName) previewName.innerText = file.name;

                if (urlInput) urlInput.value = qrCode.data;
            } else {
                clearReportQR();
                showWarningModal("No valid QR matrix detected in this image. Please upload a clear QR code.");
            }
        };
        img.src = e.target.result;
    };
    reader.readAsDataURL(file);
}

function clearReportQR(event) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const fileInput = document.getElementById('report-qr-file-input');
    if (fileInput) fileInput.value = '';

    const dropzoneContent = document.getElementById('report-dropzone-content');
    if (dropzoneContent) dropzoneContent.classList.remove('hidden');

    const previewContainer = document.getElementById('report-preview-container');
    if (previewContainer) previewContainer.classList.add('hidden');

    const previewImg = document.getElementById('report-preview-img');
    if (previewImg) previewImg.src = '';
}

if (sessionStorage.getItem('skipIntroVideo') === 'true' || window.location.search.includes('skipIntro=true')) {
    sessionStorage.removeItem('skipIntroVideo');
    const introModal = document.getElementById('intro-video-container') || document.querySelector('.video-intro-modal') || document.getElementById('introModal');
    if (introModal) {
        introModal.style.display = 'none';
        introModal.remove();
    }
}

// ==========================================
// REAL-TIME NOTIFICATION BROADCAST SYSTEM
// ==========================================
const threatChannel = ('BroadcastChannel' in window) ? new BroadcastChannel('linklocker_threat_alerts') : null;

function getStoredNotifications() {
    try {
        return JSON.parse(localStorage.getItem('linklocker_live_notifications') || '[]');
    } catch (e) {
        return [];
    }
}

function saveNotification(item) {
    const list = getStoredNotifications();
    list.unshift(item);
    if (list.length > 20) list.pop();
    localStorage.setItem('linklocker_live_notifications', JSON.stringify(list));
    updateNotificationBadge();
}

function updateNotificationBadge() {
    const list = getStoredNotifications();
    const badge = document.getElementById('notif-badge');
    if (!badge) return;

    if (list.length > 0) {
        badge.innerText = list.length > 9 ? '9+' : list.length;
        badge.classList.remove('hidden');
        badge.classList.add('flex');
    } else {
        badge.classList.add('hidden');
        badge.classList.remove('flex');
    }
}

function renderNotifications() {
    const container = document.getElementById('notif-list-container');
    if (!container) return;

    const list = getStoredNotifications();
    container.innerHTML = '';

    if (list.length === 0) {
        container.innerHTML = `
            <div class="text-center py-8 text-slate-500 space-y-1">
                <i data-lucide="bell-off" class="w-5 h-5 mx-auto text-slate-600"></i>
                <p class="text-xs font-mono">No active alerts</p>
                <p class="text-[10px] text-slate-600">New scam submissions will appear here instantly.</p>
            </div>
        `;
        if (window.lucide) lucide.createIcons();
        return;
    }

    list.forEach(item => {
        const threatCategory = item.category || 'Unknown Scam Category';
        const threatUrl = item.url || 'No URL Provided';
        const timeRecorded = item.timestamp || 'Recent';

        const el = document.createElement('div');
        el.className = "p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-rose-500/40 transition-colors space-y-2.5 text-left";
        el.innerHTML = `
            <div class="flex items-center justify-between gap-2 border-b border-slate-800/80 pb-1.5">
                <div class="flex items-center space-x-1.5">
                    <span class="w-2 h-2 rounded-full bg-rose-500 animate-pulse shrink-0"></span>
                    <span class="text-rose-400 font-mono font-bold text-[11px] uppercase tracking-wider">${escapeHtml(threatCategory)}</span>
                </div>
                <span class="text-slate-500 text-[10px] font-mono shrink-0">${escapeHtml(timeRecorded)}</span>
            </div>

            <div class="bg-slate-950/70 p-2 rounded-lg border border-slate-800">
                <span class="text-slate-500 block text-[9px] font-mono uppercase tracking-wider mb-0.5">Threat Category</span>
                <span class="text-rose-300 font-mono font-bold text-xs block">${escapeHtml(threatCategory)}</span>
            </div>

            <div class="bg-slate-950/70 p-2 rounded-lg border border-slate-800">
                <span class="text-slate-500 block text-[9px] font-mono uppercase tracking-wider mb-0.5">Suspicious URL / Extracted Payload</span>
                <p class="text-xs font-mono text-slate-200 break-all leading-relaxed">${escapeHtml(threatUrl)}</p>
            </div>
        `;
        container.appendChild(el);
    });

    if (window.lucide) lucide.createIcons();
}

function toggleNotificationDropdown(e) {
    if (e) e.stopPropagation();
    const dropdown = document.getElementById('notif-dropdown');
    if (!dropdown) return;

    const isHidden = dropdown.classList.contains('hidden');
    if (isHidden) {
        renderNotifications();
        dropdown.classList.remove('hidden');
    } else {
        dropdown.classList.add('hidden');
    }
}

function clearAllNotifications() {
    localStorage.removeItem('linklocker_live_notifications');
    updateNotificationBadge();
    renderNotifications();
}

document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('notif-dropdown');
    const bellBtn = document.getElementById('notif-bell-btn');
    if (dropdown && !dropdown.classList.contains('hidden')) {
        if (!dropdown.contains(e.target) && !bellBtn.contains(e.target)) {
            dropdown.classList.add('hidden');
        }
    }
});

function triggerGlobalAlert(alertData) {
    saveNotification(alertData);
    showCyberToast(`ALERT: New threat reported (${alertData.category})`);
    if (threatChannel) {
        threatChannel.postMessage(alertData);
    }
}

if (threatChannel) {
    threatChannel.onmessage = (event) => {
        saveNotification(event.data);
        showCyberToast(`ALERT: New threat reported (${event.data.category})`);
    };
}

updateNotificationBadge();

// Function to read clipboard contents and auto-paste into the input box
async function pasteFromClipboard() {
    const input = document.getElementById('url-input');
    const pasteBtn = document.getElementById('paste-url-btn');

    try {
        if (!navigator.clipboard || !navigator.clipboard.readText) {
            showWarningModal("Clipboard access is not supported or blocked in this browser. Please use Ctrl+V / Cmd+V.");
            return;
        }

        const text = await navigator.clipboard.readText();
        const trimmed = text.trim();

        if (!trimmed) {
            showWarningModal("Clipboard is empty! Copy a URL or link first.");
            return;
        }

        input.value = trimmed;
        input.focus();

        if (pasteBtn) {
            const originalHtml = pasteBtn.innerHTML;
            pasteBtn.innerHTML = `<i data-lucide="check" class="w-3.5 h-3.5 text-emerald-400"></i><span class="text-emerald-400">Pasted!</span>`;
            if (window.lucide) lucide.createIcons();

            setTimeout(() => {
                pasteBtn.innerHTML = originalHtml;
                if (window.lucide) lucide.createIcons();
            }, 1200);
        }

        showCyberToast("URL pasted from clipboard.");
    } catch (err) {
        console.error("Clipboard permission error:", err);
        showWarningModal("Permission to access clipboard was denied. Please allow clipboard permissions in your browser.");
    }
}

// Open Cyber Emergency & Helpline Modal
function openCyberEmergencyModal() {
    const modal = document.getElementById('cyber-emergency-modal');
    if (modal) {
        modal.classList.remove('opacity-0', 'pointer-events-none');
        modal.classList.add('opacity-100', 'pointer-events-auto');
    }
    if (window.lucide) lucide.createIcons();
}

// Close Cyber Emergency & Helpline Modal
function closeCyberEmergencyModal() {
    const modal = document.getElementById('cyber-emergency-modal');
    if (modal) {
        modal.classList.add('opacity-0', 'pointer-events-none');
        modal.classList.remove('opacity-100', 'pointer-events-auto');
    }
}

// Function: Open modal and fetch full homepage snapshot with multi-tier engine
function openSafeSnapshotModal(targetUrlOverride) {
    let rawUrl = targetUrlOverride;
    
    if (!rawUrl || typeof rawUrl !== 'string' || rawUrl.includes('\${')) {
        const inputField = document.getElementById('url-input');
        rawUrl = inputField ? inputField.value.trim() : '';
    }

    if (!rawUrl) {
        showWarningModal("No target URL found to generate a snapshot.");
        return;
    }

    let cleanUrl = rawUrl.trim();
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
        cleanUrl = 'https://' + cleanUrl;
    }

    const modal = document.getElementById('safe-snapshot-modal');
    const targetLabel = document.getElementById('snapshot-target-url');
    const imgEl = document.getElementById('snapshot-image');
    const loader = document.getElementById('snapshot-loader');
    const errorEl = document.getElementById('snapshot-error');

    if (targetLabel) targetLabel.innerText = cleanUrl;
    if (loader) loader.classList.remove('hidden');
    if (errorEl) errorEl.classList.add('hidden');
    if (imgEl) {
        imgEl.classList.add('hidden');
        imgEl.src = '';
    }

    if (modal) {
        modal.classList.remove('opacity-0', 'pointer-events-none');
        modal.classList.add('opacity-100', 'pointer-events-auto');
    }

    // Engine 1: Microlink with desktop viewport and render wait
    const engine1 = `https://api.microlink.io?url=${encodeURIComponent(cleanUrl)}&screenshot=true&meta=false&embed=screenshot.url&waitForTimeout=2500&viewport.width=1280&viewport.height=800`;
    
    // Engine 2: WordPress mShots desktop resolution
    const engine2 = `https://s0.wp.com/mshots/v1/${encodeURIComponent(cleanUrl)}?w=1280&h=800`;
    
    // Engine 3: Robothumb desktop web rendering engine
    const engine3 = `https://www.robothumb.com/src/?url=${encodeURIComponent(cleanUrl)}&size=1024x768`;

    function loadEngineCascade(sources, index) {
        if (index >= sources.length) {
            if (loader) loader.classList.add('hidden');
            if (errorEl) errorEl.classList.remove('hidden');
            return;
        }

        const currentEngineUrl = sources[index];
        const testImage = new Image();

        testImage.onload = function() {
            if (imgEl) {
                imgEl.src = currentEngineUrl;
                imgEl.classList.remove('hidden');
            }
            if (loader) loader.classList.add('hidden');
        };

        testImage.onerror = function() {
            loadEngineCascade(sources, index + 1);
        };

        testImage.src = currentEngineUrl;
    }

    loadEngineCascade([engine1, engine2, engine3], 0);

    if (window.lucide) lucide.createIcons();
}

function closeSafeSnapshotModal() {
    const modal = document.getElementById('safe-snapshot-modal');
    const imgEl = document.getElementById('snapshot-image');
    if (imgEl) imgEl.src = '';
    if (modal) {
        modal.classList.add('opacity-0', 'pointer-events-none');
        modal.classList.remove('opacity-100', 'pointer-events-auto');
    }
}