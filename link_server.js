import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import OpenAI from "openai";
import dns from "node:dns/promises";
import net from "node:net";

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 3000);
const OPENAI_MODEL = process.env.OPENAI_MODEL || "";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";

const openai = OPENAI_API_KEY
    ? new OpenAI({ apiKey: OPENAI_API_KEY })
    : null;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

/* =========================================================
   URL NORMALIZATION
========================================================= */

function normalizeUrl(input) {
    let value = String(input || "").trim();

    if (!value) {
        throw new Error("URL is required.");
    }

    if (!/^https?:\/\//i.test(value)) {
        value = "https://" + value;
    }

    let parsed;

    try {
        parsed = new URL(value);
    } catch {
        throw new Error("Invalid URL.");
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Only HTTP and HTTPS URLs are supported.");
    }

    return parsed.toString();
}

/* =========================================================
   IP / SSRF PROTECTION
========================================================= */

function isPrivateIPv4(ip) {
    const parts = ip.split(".").map(Number);

    if (
        parts.length !== 4 ||
        parts.some(
            n =>
                !Number.isInteger(n) ||
                n < 0 ||
                n > 255
        )
    ) {
        return false;
    }

    const [a, b] = parts;

    return (
        a === 0 ||
        a === 10 ||
        a === 127 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254)
    );
}

function isPrivateIPv6(ip) {
    const value = ip.toLowerCase();

    return (
        value === "::" ||
        value === "::1" ||
        value.startsWith("fc") ||
        value.startsWith("fd") ||
        /^fe[89ab]/.test(value)
    );
}

async function isBlockedHost(hostname) {
    const host = hostname.toLowerCase();

    const blockedNames = [
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback"
    ];

    if (
        blockedNames.includes(host) ||
        host.endsWith(".localhost") ||
        host.endsWith(".local") ||
        host.endsWith(".internal")
    ) {
        return true;
    }

    const family = net.isIP(host);

    if (family === 4) {
        return isPrivateIPv4(host);
    }

    if (family === 6) {
        return isPrivateIPv6(host);
    }

    try {
        const addresses = await dns.lookup(host, {
            all: true,
            verbatim: true
        });

        return addresses.some(item => {
            if (item.family === 4) {
                return isPrivateIPv4(item.address);
            }

            return isPrivateIPv6(item.address);
        });
    } catch {
        return false;
    }
}

/* =========================================================
   DOMAIN HELPERS
========================================================= */

function getRootDomain(hostname) {
    const parts = hostname
        .split(".")
        .filter(Boolean);

    if (parts.length <= 2) {
        return hostname;
    }

    const suffix = parts.slice(-2).join(".");

    const specialSuffixes = [
        "co.uk",
        "org.uk",
        "com.au",
        "co.in",
        "com.br",
        "co.jp"
    ];

    if (specialSuffixes.includes(suffix)) {
        return parts.slice(-3).join(".");
    }

    return suffix;
}

function getSubdomain(hostname) {
    const root = getRootDomain(hostname);

    if (hostname === root) {
        return "";
    }

    if (hostname.endsWith("." + root)) {
        return hostname.slice(
            0,
            -(root.length + 1)
        );
    }

    return "";
}

function isDomainUnder(hostname, domain) {
    const host = hostname.toLowerCase();
    const target = domain.toLowerCase();

    return (
        host === target ||
        host.endsWith("." + target)
    );
}

/* =========================================================
   URL PARSER
========================================================= */

function parseUrl(urlString) {
    const url = new URL(urlString);

    const queryParams = {};

    for (const [key, value] of url.searchParams.entries()) {
        if (queryParams[key] === undefined) {
            queryParams[key] = value;
        } else if (Array.isArray(queryParams[key])) {
            queryParams[key].push(value);
        } else {
            queryParams[key] = [
                queryParams[key],
                value
            ];
        }
    }

    return {
        raw: urlString,

        protocol: url.protocol.replace(":", ""),

        hostname: url.hostname,

        domain: url.hostname,

        rootDomain: getRootDomain(url.hostname),

        subdomain: getSubdomain(url.hostname),

        port:
            url.port ||
            (
                url.protocol === "https:"
                    ? "443"
                    : "80"
            ),

        path: url.pathname || "/",

        pathSegments:
            url.pathname
                .split("/")
                .filter(Boolean),

        query:
            url.search
                ? url.search.substring(1)
                : "",

        queryParams,

        fragment:
            url.hash
                ? url.hash.substring(1)
                : "",

        length: urlString.length,

        encodedContent:
            /%[0-9a-f]{2}/i.test(urlString)
    };
}

/* =========================================================
   TEXT HELPERS
========================================================= */

function cleanText(value) {
    return String(value || "")
        .replace(/\s+/g, " ")
        .replace(/\u00a0/g, " ")
        .trim();
}

function stripHtml(html) {
    return String(html || "")
        .replace(
            /<script[\s\S]*?<\/script>/gi,
            " "
        )
        .replace(
            /<style[\s\S]*?<\/style>/gi,
            " "
        )
        .replace(
            /<noscript[\s\S]*?<\/noscript>/gi,
            " "
        )
        .replace(
            /<svg[\s\S]*?<\/svg>/gi,
            " "
        )
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/\s+/g, " ")
        .trim();
}

function extractTagContent(html, tagName) {
    const regex = new RegExp(
        `<${tagName}\\b[^>]*>([\\s\\S]*?)<\\/${tagName}>`,
        "i"
    );

    const match = String(html || "").match(regex);

    return match
        ? cleanText(stripHtml(match[1]))
        : "";
}

function extractMeta(html, name) {
    const safeName = String(name)
        .replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

    const regex1 = new RegExp(
        `<meta\\b[^>]*(?:name|property)=["']${safeName}["'][^>]*content=["']([^"']*)["'][^>]*>`,
        "i"
    );

    const regex2 = new RegExp(
        `<meta\\b[^>]*content=["']([^"']*)["'][^>]*(?:name|property)=["']${safeName}["'][^>]*>`,
        "i"
    );

    const match =
        String(html || "").match(regex1) ||
        String(html || "").match(regex2);

    return match
        ? cleanText(match[1])
        : "";
}

function extractHeadings(html) {
    const results = [];

    const regex =
        /<(h[1-3])\b[^>]*>([\s\S]*?)<\/\1>/gi;

    let match;

    while (
        (match = regex.exec(String(html || ""))) !== null
    ) {
        const text = cleanText(
            stripHtml(match[2])
        );

        if (text) {
            results.push({
                level: match[1].toUpperCase(),
                text
            });
        }

        if (results.length >= 30) {
            break;
        }
    }

    return results;
}

function extractLinks(html, baseUrl) {
    const results = [];

    const regex =
        /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

    let match;

    while (
        (match = regex.exec(String(html || ""))) !== null
    ) {
        if (results.length >= 100) {
            break;
        }

        const href = match[1].trim();

        if (!href || href.startsWith("#")) {
            continue;
        }

        try {
            results.push({
                url: new URL(
                    href,
                    baseUrl
                ).toString(),

                text: cleanText(
                    stripHtml(match[2])
                )
            });
        } catch {
            // Ignore invalid URLs.
        }
    }

    return results;
}

function extractImages(html, baseUrl) {
    const results = [];

    const regex =
        /<img\b[^>]*src\s*=\s*["']([^"']+)["'][^>]*>/gi;

    let match;

    while (
        (match = regex.exec(String(html || ""))) !== null
    ) {
        if (results.length >= 50) {
            break;
        }

        try {
            results.push(
                new URL(
                    match[1],
                    baseUrl
                ).toString()
            );
        } catch {
            // Ignore invalid image URLs.
        }
    }

    return results;
}

/* =========================================================
   KNOWN SERVICES
========================================================= */

function detectKnownService(url) {
    const host = url.hostname.toLowerCase();
    const path = url.pathname.toLowerCase();

    /* Google Sheets */

    if (
        host === "docs.google.com" &&
        path.startsWith("/spreadsheets/")
    ) {
        return {
            provider: "Google",

            name: "Google Sheets",

            type: "Spreadsheet / Collaboration",

            category: "Google Workspace",

            purpose:
                "A Google Sheets document used for spreadsheets, tables, calculations, shared data, or collaboration.",

            summary:
                "This link points to Google Sheets.",

            confidence: "High",

            service: "Google Sheets",

            contentDescription:
                "A spreadsheet containing rows, columns, tables, formulas, or shared data. Actual contents depend on sharing permissions.",

            official: true
        };
    }

    /* Google Docs */

    if (
        host === "docs.google.com" &&
        path.startsWith("/document/")
    ) {
        return {
            provider: "Google",

            name: "Google Docs",

            type: "Document / Collaboration",

            category: "Google Workspace",

            purpose:
                "A document hosted by Google Docs.",

            summary:
                "This link points to Google Docs.",

            confidence: "High",

            service: "Google Docs",

            contentDescription:
                "A shared Google document. Actual contents depend on access permissions.",

            official: true
        };
    }

    /* Google Forms */

    if (
        host === "docs.google.com" &&
        path.startsWith("/forms/")
    ) {
        return {
            provider: "Google",

            name: "Google Forms",

            type: "Online Form",

            category: "Google Workspace",

            purpose:
                "An online form used to collect information and responses.",

            summary:
                "This link points to Google Forms.",

            confidence: "High",

            service: "Google Forms",

            contentDescription:
                "An online form that may contain questions, fields, choices, and response collection.",

            official: true
        };
    }

    if (host === "forms.gle") {
        return {
            provider: "Google",

            name: "Google Forms",

            type: "Online Form / Short Link",

            category: "Google Workspace",

            purpose:
                "A shortened Google Forms link.",

            summary:
                "This link uses Google's forms.gle service.",

            confidence: "High",

            service: "Google Forms",

            contentDescription:
                "A Google Forms destination. Actual contents depend on the final destination and permissions.",

            official: true
        };
    }

    /* Google Drive */

    if (isDomainUnder(host, "drive.google.com")) {
        return {
            provider: "Google",

            name: "Google Drive",

            type: "Cloud Storage / File Sharing",

            category: "Google Workspace",

            purpose:
                "A Google Drive file or folder.",

            summary:
                "This link points to Google Drive.",

            confidence: "High",

            service: "Google Drive",

            contentDescription:
                "A file or folder hosted by Google Drive.",

            official: true
        };
    }

    /* Google Slides */

    if (
        host === "docs.google.com" &&
        path.startsWith("/presentation/")
    ) {
        return {
            provider: "Google",

            name: "Google Slides",

            type: "Presentation / Collaboration",

            category: "Google Workspace",

            purpose:
                "A presentation hosted by Google Slides.",

            summary:
                "This link points to Google Slides.",

            confidence: "High",

            service: "Google Slides",

            contentDescription:
                "A presentation containing slides and visual content.",

            official: true
        };
    }

    /* YouTube */

    if (
        host === "youtube.com" ||
        host === "www.youtube.com" ||
        host === "youtu.be" ||
        isDomainUnder(host, "youtube.com")
    ) {
        return {
            provider: "Google",

            name: "YouTube",

            type: "Video Platform",

            category: "Entertainment / Media",

            purpose:
                "A video hosting and streaming platform.",

            summary:
                "This link points to YouTube.",

            confidence: "High",

            service: "YouTube",

            contentDescription:
                "Video content, channels, comments, or media pages.",

            official: true
        };
    }

    /* GitHub */

    if (
        host === "github.com" ||
        isDomainUnder(host, "github.com")
    ) {
        return {
            provider: "GitHub",

            name: "GitHub",

            type: "Code Hosting / Development",

            category: "Software Development",

            purpose:
                "A platform for source code, repositories, issues, projects, and developer collaboration.",

            summary:
                "This link points to GitHub.",

            confidence: "High",

            service: "GitHub",

            contentDescription:
                "Code repositories, files, documentation, issues, releases, or developer projects.",

            official: true
        };
    }

    /* Microsoft */

    if (
        isDomainUnder(host, "microsoft.com") ||
        isDomainUnder(host, "microsoftonline.com") ||
        isDomainUnder(host, "office.com") ||
        isDomainUnder(host, "sharepoint.com") ||
        isDomainUnder(host, "outlook.com")
    ) {
        return {
            provider: "Microsoft",

            name: "Microsoft Service",

            type: "Microsoft Online Service",

            category: "Productivity / Cloud",

            purpose:
                "A Microsoft online service or cloud platform.",

            summary:
                "This link points to a Microsoft-controlled domain.",

            confidence: "High",

            service: "Microsoft",

            contentDescription:
                "Microsoft-hosted content or services.",

            official: true
        };
    }

    /* LinkedIn */

    if (
        host === "linkedin.com" ||
        isDomainUnder(host, "linkedin.com")
    ) {
        return {
            provider: "LinkedIn",

            name: "LinkedIn",

            type: "Professional Social Network",

            category: "Social Media",

            purpose:
                "A professional networking and career platform.",

            summary:
                "This link points to LinkedIn.",

            confidence: "High",

            service: "LinkedIn",

            contentDescription:
                "Professional profiles, company pages, jobs, posts, and networking content.",

            official: true
        };
    }

    /* Instagram */

    if (
        host === "instagram.com" ||
        isDomainUnder(host, "instagram.com")
    ) {
        return {
            provider: "Instagram",

            name: "Instagram",

            type: "Social Media",

            category: "Social Media",

            purpose:
                "A social media platform for photos, videos, profiles, and messages.",

            summary:
                "This link points to Instagram.",

            confidence: "High",

            service: "Instagram",

            contentDescription:
                "Photos, videos, profiles, posts, reels, and social content.",

            official: true
        };
    }

    /* Facebook */

    if (
        host === "facebook.com" ||
        isDomainUnder(host, "facebook.com")
    ) {
        return {
            provider: "Meta",

            name: "Facebook",

            type: "Social Media",

            category: "Social Media",

            purpose:
                "A social media platform for profiles, pages, posts, groups, and communication.",

            summary:
                "This link points to Facebook.",

            confidence: "High",

            service: "Facebook",

            contentDescription:
                "Profiles, pages, posts, groups, or social media content.",

            official: true
        };
    }

    return null;
}

/* =========================================================
   TEST / DEV / STAGING DETECTION
========================================================= */

function detectNonProductionDomain(url) {
    const host = url.hostname.toLowerCase();

    const suspiciousLabels = [
        "test",
        "testing",
        "dev",
        "development",
        "staging",
        "stage",
        "demo",
        "sandbox",
        "qa",
        "uat",
        "preview",
        "temp",
        "temporary",
        "fake",
        "mock"
    ];

    const labels = host.split(".");

    return [
        ...new Set(
            labels.filter(label =>
                suspiciousLabels.includes(label)
            )
        )
    ];
}

/* =========================================================
   PAYMENT / ACCOUNT DETECTION
========================================================= */

function detectPaymentSignals(url) {
    const text = (
        url.hostname +
        " " +
        url.pathname +
        " " +
        url.search
    ).toLowerCase();

    const paymentWords = [
        "payment",
        "pay",
        "checkout",
        "billing",
        "invoice",
        "card",
        "credit-card",
        "debit-card",
        "transaction",
        "wallet",
        "bank",
        "secure-payment",
        "payment-verification"
    ];

    const accountWords = [
        "verify-account",
        "account-verification",
        "confirm-account",
        "secure-login",
        "verify-payment",
        "payment-verification",
        "credential",
        "password",
        "signin",
        "sign-in",
        "login"
    ];

    const paymentHits = [
        ...new Set(
            paymentWords.filter(word =>
                text.includes(word)
            )
        )
    ];

    const accountHits = [
        ...new Set(
            accountWords.filter(word =>
                text.includes(word)
            )
        )
    ];

    return {
        paymentHits,
        accountHits
    };
}

/* =========================================================
   BRAND DOMAINS
========================================================= */

const BRANDS = {
    google: [
        "google.com",
        "google.co.in",
        "googleapis.com",
        "googleusercontent.com",
        "gstatic.com"
    ],

    microsoft: [
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "outlook.com",
        "office.com"
    ],

    paypal: [
        "paypal.com",
        "paypalobjects.com"
    ],

    apple: [
        "apple.com",
        "icloud.com"
    ],

    amazon: [
        "amazon.com",
        "amazon.in",
        "amazonaws.com"
    ],

    facebook: [
        "facebook.com",
        "fb.com",
        "meta.com"
    ],

    instagram: [
        "instagram.com"
    ],

    whatsapp: [
        "whatsapp.com",
        "whatsapp.net"
    ],

    netflix: [
        "netflix.com"
    ],

    linkedin: [
        "linkedin.com"
    ],

    github: [
        "github.com",
        "githubusercontent.com"
    ],

    adobe: [
        "adobe.com"
    ],

    dropbox: [
        "dropbox.com"
    ],

    docusign: [
        "docusign.com"
    ]
};

/* =========================================================
   BRAND IMPERSONATION
========================================================= */

function detectBrandImpersonation(hostname) {
    const host = hostname.toLowerCase();

    const labels = host
        .split(".")
        .filter(Boolean);

    const rootDomain =
        getRootDomain(host);

    const detected = [];

    for (const brand of Object.keys(BRANDS)) {
        const mentioned =
            labels.some(label =>
                label === brand ||
                label.includes(brand)
            );

        if (!mentioned) {
            continue;
        }

        const official =
            BRANDS[brand].some(
                officialDomain =>
                    host === officialDomain ||
                    host.endsWith(
                        "." + officialDomain
                    )
            );

        if (!official) {
            detected.push({
                brand,
                rootDomain,
                hostname: host
            });
        }
    }

    return detected;
}

/* =========================================================
   KNOWN PHISHING DETECTION
========================================================= */

function detectKnownPhishingCampaign(url) {
    const hostname =
        url.hostname.toLowerCase();

    const pathname =
        url.pathname.toLowerCase();

    const formValue =
        url.searchParams
            .get("form")
            ?.toLowerCase() || "";

    const matches = [];

    if (
        hostname ===
        "forms.google.ss-o.com"
    ) {
        matches.push({
            type: "critical",

            title:
                "Known phishing domain",

            detail:
                "This hostname matches a known fake Google Forms phishing pattern.",

            points: 45
        });
    }

    if (
        hostname.includes("google") &&
        getRootDomain(hostname) !==
            "google.com"
    ) {
        matches.push({
            type: "critical",

            title:
                "Google brand impersonation",

            detail:
                `The hostname contains "google", but the registered root domain is ${getRootDomain(hostname)}.`,

            points: 28
        });
    }

    if (
        hostname ===
            "forms.google.ss-o.com" &&
        pathname ===
            "/generation_form.php"
    ) {
        matches.push({
            type: "critical",

            title:
                "Known phishing endpoint",

            detail:
                "The URL matches a known phishing endpoint pattern.",

            points: 22
        });
    }

    if (
        hostname ===
            "forms.google.ss-o.com" &&
        formValue ===
            "opportunitysec"
    ) {
        matches.push({
            type: "critical",

            title:
                "Known phishing campaign parameter",

            detail:
                "The URL contains a parameter associated with the known phishing pattern.",

            points: 20
        });
    }

    if (
        hostname.startsWith("forms.google.") &&
        getRootDomain(hostname) !==
            "google.com"
    ) {
        matches.push({
            type: "critical",

            title:
                "Fake Google Forms hostname",

            detail:
                "The hostname resembles Google's Forms service while using a different root domain.",

            points: 25
        });
    }

    return matches;
}

/* =========================================================
   SECURITY ANALYSIS
========================================================= */

function analyzeSecurity(
    rawUrl,
    fetchResult = null,
    knownService = null,
    fetchError = ""
) {
    const url = new URL(rawUrl);

    const hostname =
        url.hostname.toLowerCase();

    const indicators = [];

    let riskPoints = 0;

    function add(
        type,
        title,
        detail,
        points
    ) {
        riskPoints += points;

        indicators.push({
            type,
            title,
            detail,
            points
        });
    }

    /* -----------------------------------------------
       Known phishing
    ----------------------------------------------- */

    const phishing =
        detectKnownPhishingCampaign(url);

    for (const item of phishing) {
        add(
            item.type,
            item.title,
            item.detail,
            item.points
        );
    }

    /* -----------------------------------------------
       HTTPS
    ----------------------------------------------- */

    if (url.protocol !== "https:") {
        add(
            "danger",
            "HTTPS is not used",
            "The destination uses HTTP instead of encrypted HTTPS.",
            15
        );
    } else {
        indicators.push({
            type: "safe",

            title:
                "HTTPS is enabled",

            detail:
                "HTTPS encrypts the connection, but HTTPS alone does not prove that a website is legitimate.",

            points: 0
        });
    }

    /* -----------------------------------------------
       Test / staging / development domain
    ----------------------------------------------- */

    const nonProductionLabels =
        detectNonProductionDomain(url);

    if (
        nonProductionLabels.length
    ) {
        add(
            "warning",

            "Test or non-production domain",

            "The hostname contains a test/development environment label: " +
                nonProductionLabels.join(", ") +
                ". This may indicate a testing, staging, demo, sandbox, or temporary website.",

            18
        );
    }

    /* -----------------------------------------------
       Payment signals
    ----------------------------------------------- */

    const paymentSignals =
        detectPaymentSignals(url);

    if (
        paymentSignals.paymentHits.length
    ) {
        add(
            "warning",

            "Payment-related URL detected",

            "The URL contains payment-related wording: " +
                paymentSignals.paymentHits.join(", ") +
                ".",

            12
        );
    }

    if (
        paymentSignals.accountHits.length
    ) {
        add(
            "danger",

            "Account/payment verification wording",

            "The URL contains verification or account-related wording: " +
                paymentSignals.accountHits.join(", ") +
                ".",

            15
        );
    }

    /* -----------------------------------------------
       Raw IP
    ----------------------------------------------- */

    if (net.isIP(hostname)) {
        add(
            "danger",

            "IP address host",

            "The destination uses a raw IP address instead of a normal domain name.",

            20
        );
    }

    /* -----------------------------------------------
       Punycode
    ----------------------------------------------- */

    if (hostname.includes("xn--")) {
        add(
            "danger",

            "Punycode domain",

            "The hostname contains an encoded internationalized domain label.",

            18
        );
    }

    /* -----------------------------------------------
       Deep subdomain
    ----------------------------------------------- */

    const labels =
        hostname
            .split(".")
            .filter(Boolean);

    if (labels.length >= 5) {
        add(
            "warning",

            "Deep subdomain structure",

            "The hostname contains an unusually deep subdomain structure.",

            8
        );
    }

    /* -----------------------------------------------
       @ symbol
    ----------------------------------------------- */

    if (rawUrl.includes("@")) {
        add(
            "danger",

            "@ character detected",

            "The URL contains @ syntax that can be used to disguise the actual destination.",

            18
        );
    }

    /* -----------------------------------------------
       URL shorteners
    ----------------------------------------------- */

    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
        "ow.ly",
        "buff.ly",
        "rb.gy",
        "rebrand.ly"
    ];

    if (
        shorteners.some(
            domain =>
                hostname === domain ||
                hostname.endsWith("." + domain)
        )
    ) {
        add(
            "warning",

            "URL shortener detected",

            "A shortened URL can hide the final destination.",

            8
        );
    }

    /* -----------------------------------------------
       Suspicious words
    ----------------------------------------------- */

    const suspiciousWords = [
        "login",
        "log-in",
        "signin",
        "sign-in",
        "verify",
        "verification",
        "password",
        "credential",
        "wallet",
        "payment",
        "billing",
        "authenticate",
        "authentication",
        "unlock",
        "recover",
        "urgent",
        "bank"
    ];

    const combinedText = (
        hostname +
        " " +
        url.pathname +
        " " +
        url.search
    ).toLowerCase();

    const wordHits = [
        ...new Set(
            suspiciousWords.filter(
                word =>
                    combinedText.includes(word)
            )
        )
    ];

    if (wordHits.length) {
        add(
            "warning",

            "Security-sensitive wording detected",

            "Detected: " +
                wordHits
                    .slice(0, 10)
                    .join(", "),

            Math.min(
                18,
                5 + wordHits.length * 2
            )
        );
    }

    /* -----------------------------------------------
       Redirect parameters
    ----------------------------------------------- */

    const redirectKeys = [
        "redirect",
        "redirect_url",
        "redirect_uri",
        "target",
        "next",
        "dest",
        "destination",
        "return",
        "returnurl",
        "return_url",
        "continue",
        "callback",
        "goto",
        "forward"
    ];

    const redirectHits =
        redirectKeys.filter(
            key =>
                url.searchParams.has(key)
        );

    if (redirectHits.length) {
        add(
            "warning",

            "Redirect parameter detected",

            "The URL contains redirect-style parameter(s): " +
                redirectHits.join(", "),

            10
        );
    }

    /* -----------------------------------------------
       Encoded URL
    ----------------------------------------------- */

    if (
        /%[0-9a-f]{2}/i.test(rawUrl)
    ) {
        add(
            "warning",

            "Encoded URL content",

            "The URL contains percent-encoded content.",

            3
        );
    }

    /* -----------------------------------------------
       Long URL
    ----------------------------------------------- */

    if (rawUrl.length > 180) {
        add(
            "warning",

            "Long URL",

            "The URL is unusually long.",

            5
        );
    }

    if (rawUrl.length > 300) {
        add(
            "warning",

            "Extremely long URL",

            "The URL is substantially longer than a typical web address.",

            8
        );
    }

    /* -----------------------------------------------
       Non-standard port
    ----------------------------------------------- */

    if (
        url.port &&
        !["80", "443"].includes(url.port)
    ) {
        add(
            "warning",

            "Non-standard port",

            "The URL uses a non-standard web port.",

            6
        );
    }

    /* -----------------------------------------------
       Executable / archive
    ----------------------------------------------- */

    if (
        /\.(exe|scr|bat|cmd|msi|apk|dmg|jar|iso|zip|rar)(?:$|[?#])/i.test(
            url.pathname
        )
    ) {
        add(
            "danger",

            "Executable or archive download path",

            "The URL points to a potentially dangerous executable or archive file type.",

            22
        );
    }

    /* -----------------------------------------------
       Suspicious hostname wording
    ----------------------------------------------- */

    const hostnameWords = [
        "secure",
        "verify",
        "verification",
        "login",
        "signin",
        "account",
        "support",
        "alert",
        "security",
        "update",
        "confirm",
        "official",
        "customer"
    ];

    const hostWordHits = [
        ...new Set(
            hostnameWords.filter(
                word =>
                    hostname.includes(word)
            )
        )
    ];

    if (
        hostWordHits.length &&
        phishing.length === 0
    ) {
        add(
            "warning",

            "Suspicious hostname wording",

            "Detected: " +
                hostWordHits.join(", "),

            Math.min(
                12,
                hostWordHits.length * 3
            )
        );
    }

    /* -----------------------------------------------
       Hyphen-heavy hostname
    ----------------------------------------------- */

    const hyphenCount =
        (hostname.match(/-/g) || [])
            .length;

    if (hyphenCount >= 3) {
        add(
            "warning",

            "Hyphen-heavy hostname",

            "The hostname contains several hyphen-separated labels.",

            5
        );
    }

    /* -----------------------------------------------
       Brand impersonation
    ----------------------------------------------- */

    const brands =
        detectBrandImpersonation(
            hostname
        );

    for (const item of brands) {
        add(
            "danger",

            `${item.brand} brand impersonation`,

            `The hostname contains ${item.brand}, but the actual registered root domain is ${item.rootDomain}.`,

            22
        );
    }

    /* -----------------------------------------------
       Redirect chain
    ----------------------------------------------- */

    if (
        fetchResult &&
        fetchResult.redirects &&
        fetchResult.redirects.length
    ) {
        add(
            "warning",

            "Redirect chain detected",

            "The destination redirected " +
                fetchResult.redirects.length +
                " time(s).",

            Math.min(
                12,
                fetchResult.redirects.length * 4
            )
        );
    }

    /* -----------------------------------------------
       HTTP error
    ----------------------------------------------- */

    if (
        fetchResult &&
        fetchResult.status >= 400
    ) {
        add(
            "warning",

            "Destination returned an error",

            "The website responded with HTTP " +
                fetchResult.status +
                ".",

            6
        );
    }

    /* -----------------------------------------------
       WEBSITE NOT VERIFIED
       
       IMPORTANT FIX
    ----------------------------------------------- */

    if (fetchError) {
        add(
            "warning",

            "Website could not be verified",

            "SAFNEX NOVA could not retrieve the destination page. The result therefore cannot be treated as fully verified.",

            15
        );
    }

    /* -----------------------------------------------
       No fetch and no known service
    ----------------------------------------------- */

    if (
        !fetchResult &&
        !knownService
    ) {
        add(
            "warning",

            "Website identity is unverified",

            "The destination was not successfully retrieved and is not recognized as a known service.",

            10
        );
    }

    /* =================================================
       SCORE
       
       IMPORTANT:
       We no longer use:
       
       score = 100 - riskPoints
       
       as the only calculation.
    ================================================= */

    let securityScore =
        100 - riskPoints;

    /* Known official services get only a small benefit. */

    if (
        knownService &&
        knownService.official
    ) {
        securityScore += 4;
    }

    /* Successfully fetched destination gives evidence. */

    if (
        fetchResult &&
        fetchResult.status >= 200 &&
        fetchResult.status < 400
    ) {
        securityScore += 5;
    }

    /* -----------------------------------------------
       No fetch = cannot be 100
    ----------------------------------------------- */

    if (!fetchResult) {
        securityScore =
            Math.min(
                securityScore,
                knownService
                    ? 88
                    : 78
            );
    }

    /* -----------------------------------------------
       Test/dev/staging + unreachable
       
       This specifically fixes:
       test.safnexnova.com
    ----------------------------------------------- */

    if (
        nonProductionLabels.length &&
        !fetchResult
    ) {
        securityScore =
            Math.min(
                securityScore,
                65
            );
    }

    /* -----------------------------------------------
       Payment + account verification + unreachable
    ----------------------------------------------- */

    if (
        (
            paymentSignals.paymentHits.length ||
            paymentSignals.accountHits.length
        ) &&
        !fetchResult
    ) {
        securityScore =
            Math.min(
                securityScore,
                58
            );
    }

    /* -----------------------------------------------
       Known phishing
    ----------------------------------------------- */

    if (phishing.length) {
        securityScore =
            Math.min(
                securityScore,
                20
            );
    }

    /* -----------------------------------------------
       Clamp
    ----------------------------------------------- */

    securityScore =
        Math.max(
            0,
            Math.min(
                100,
                Math.round(
                    securityScore
                )
            )
        );

    const riskScore =
        100 - securityScore;

    /* =================================================
       CONFIDENCE
    ================================================= */

    let confidence;

    if (
        fetchResult &&
        knownService
    ) {
        confidence = "High";
    } else if (
        fetchResult
    ) {
        confidence = "Medium";
    } else {
        confidence = "Low";
    }

    /* =================================================
       VERDICT
    ================================================= */

    let verdict;

    if (phishing.length) {
        verdict = "High Risk";
    } else if (
        securityScore >= 85 &&
        fetchResult &&
        !fetchError &&
        confidence === "High"
    ) {
        verdict = "Likely Safe";
    } else if (
        securityScore >= 65
    ) {
        verdict = "Review";
    } else if (
        securityScore >= 40
    ) {
        verdict = "Suspicious";
    } else {
        verdict = "High Risk";
    }

    /* =================================================
       RISK LEVEL
    ================================================= */

    let riskLevel;

    if (
        securityScore >= 85 &&
        confidence === "High"
    ) {
        riskLevel = "LOW RISK";
    } else if (
        securityScore >= 65
    ) {
        riskLevel = "MEDIUM RISK";
    } else if (
        securityScore >= 40
    ) {
        riskLevel = "ELEVATED RISK";
    } else {
        riskLevel = "HIGH RISK";
    }

    return {
        score: securityScore,

        riskScore,

        verdict,

        riskLevel,

        confidence,

        indicators,

        knownPhishing:
            phishing.length > 0,

        verification: {
            verified:
                Boolean(fetchResult),

            contentVerified:
                Boolean(fetchResult),

            fetchError:
                fetchError || null
        },

        malwareReputation: {
            available: false,

            message:
                "No live malware reputation database is connected. This result uses URL heuristics, known indicators, website verification, and service recognition."
        }
    };
}

/* =========================================================
   WEBSITE FETCH
========================================================= */

async function fetchWebsite(startUrl) {
    let currentUrl = startUrl;

    const redirects = [];

    const MAX_REDIRECTS = 5;

    for (
        let attempt = 0;
        attempt <= MAX_REDIRECTS;
        attempt++
    ) {
        const parsed =
            new URL(currentUrl);

        if (
            await isBlockedHost(
                parsed.hostname
            )
        ) {
            throw new Error(
                "Blocked destination: private or local network address."
            );
        }

        const controller =
            new AbortController();

        const timeout =
            setTimeout(
                () =>
                    controller.abort(),
                10000
            );

        let response;

        try {
            response = await fetch(
                currentUrl,
                {
                    method: "GET",

                    redirect: "manual",

                    signal:
                        controller.signal,

                    headers: {
                        "User-Agent":
                            "SAFNEX-NOVA-Link-Analyzer/3.0",

                        "Accept":
                            "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8"
                    }
                }
            );
        } catch (error) {
            clearTimeout(timeout);

            if (
                error.name ===
                "AbortError"
            ) {
                throw new Error(
                    "Website request timed out."
                );
            }

            throw new Error(
                "Unable to fetch website: " +
                    error.message
            );
        }

        clearTimeout(timeout);

        /* Redirect */

        if (
            response.status >= 300 &&
            response.status < 400
        ) {
            const location =
                response.headers.get(
                    "location"
                );

            if (!location) {
                break;
            }

            const nextUrl =
                new URL(
                    location,
                    currentUrl
                ).toString();

            const nextParsed =
                new URL(nextUrl);

            if (
                await isBlockedHost(
                    nextParsed.hostname
                )
            ) {
                throw new Error(
                    "Redirect destination is blocked because it points to a private or local network."
                );
            }

            redirects.push({
                from: currentUrl,

                to: nextUrl,

                status:
                    response.status
            });

            currentUrl =
                nextUrl;

            continue;
        }

        const contentType =
            response.headers.get(
                "content-type"
            ) || "";

        const contentLength =
            Number(
                response.headers.get(
                    "content-length"
                ) || 0
            );

        if (
            contentLength >
            2 * 1024 * 1024
        ) {
            throw new Error(
                "Website response is larger than the 2 MB analyzer limit."
            );
        }

        const buffer =
            await response.arrayBuffer();

        if (
            buffer.byteLength >
            2 * 1024 * 1024
        ) {
            throw new Error(
                "Website response is larger than the 2 MB analyzer limit."
            );
        }

        const text =
            new TextDecoder(
                "utf-8"
            ).decode(buffer);

        return {
            requestedUrl:
                startUrl,

            finalUrl:
                currentUrl,

            status:
                response.status,

            contentType,

            redirects,

            html:
                text
        };
    }

    throw new Error(
        "Too many redirects."
    );
}

/* =========================================================
   WEBSITE DATA
========================================================= */

function extractWebsiteData(fetchResult) {
    const html =
        fetchResult.html || "";

    const title =
        extractTagContent(
            html,
            "title"
        );

    const description =
        extractMeta(
            html,
            "description"
        ) ||
        extractMeta(
            html,
            "og:description"
        );

    const headings =
        extractHeadings(html);

    const links =
        extractLinks(
            html,
            fetchResult.finalUrl
        );

    const images =
        extractImages(
            html,
            fetchResult.finalUrl
        );

    const text =
        stripHtml(html);

    return {
        title,

        description,

        headings,

        links,

        images,

        text:
            text.substring(
                0,
                15000
            ),

        textLength:
            text.length
    };
}

/* =========================================================
   FALLBACK INTELLIGENCE
========================================================= */

function fallbackWebsiteUnderstanding(
    urlInfo,
    website,
    knownService
) {
    if (knownService) {
        return {
            name:
                knownService.name,

            type:
                knownService.type,

            category:
                knownService.category,

            purpose:
                knownService.purpose,

            summary:
                knownService.summary,

            services: [
                knownService.service
            ],

            language:
                "Unknown",

            confidence:
                knownService.confidence,

            evidence: [
                "Recognized official service domain.",

                knownService.contentDescription
            ]
        };
    }

    const combined =
        [
            website?.title,
            website?.description,
            ...(website?.headings || [])
                .map(item => item.text),
            website?.text
        ]
            .join(" ")
            .toLowerCase();

    let type =
        "General Website";

    let category =
        "General website";

    let purpose =
        "Provides publicly accessible website information.";

    const services = [];

    if (
        /scrap|recycl|waste|pickup|metal|paper/
            .test(combined)
    ) {
        type =
            "Scrap & Recycling Website";

        category =
            "Scrap collection / recycling";

        purpose =
            "Provides information or services related to scrap collection, recycling, scrap selling, or pickup.";

        services.push(
            "Scrap collection",
            "Scrap pickup",
            "Recycling services"
        );
    }

    if (
        /artificial intelligence|chatbot|machine learning|ai assistant/
            .test(combined)
    ) {
        type =
            "AI / Technology Website";

        category =
            "Artificial intelligence";

        purpose =
            "Provides artificial intelligence or technology-related services.";

        services.push(
            "AI services",
            "Technology services"
        );
    }

    if (
        /shop|cart|product|buy now|add to cart|price/
            .test(combined)
    ) {
        type =
            "E-commerce Website";

        category =
            "Online shopping";

        purpose =
            "Provides products or services for users to browse or purchase.";

        services.push(
            "Product browsing",
            "Online purchasing"
        );
    }

    if (
        /booking|appointment|reserve|reservation/
            .test(combined)
    ) {
        services.push(
            "Booking or appointment functionality"
        );
    }

    if (
        /contact|support|customer service/
            .test(combined)
    ) {
        services.push(
            "Contact / customer support"
        );
    }

    if (
        /news|article|breaking|headline/
            .test(combined)
    ) {
        type =
            "News / Information Website";

        category =
            "News and information";

        purpose =
            "Provides articles, news, or informational content.";

        services.push(
            "Articles",
            "News information"
        );
    }

    return {
        name:
            website?.title ||
            urlInfo.hostname,

        type,

        category,

        purpose,

        summary:
            website?.description ||
            `The website appears to be a ${category.toLowerCase()} based on publicly visible content.`,

        services:
            [
                ...new Set(services)
            ],

        language:
            "Unknown",

        confidence:
            "Medium",

        evidence:
            [
                website?.title,

                website?.description,

                ...(website?.headings || [])
                    .slice(0, 10)
                    .map(
                        item =>
                            item.text
                    )
            ].filter(Boolean)
    };
}

/* =========================================================
   OPENAI INTELLIGENCE
========================================================= */

async function understandWebsiteWithAI(
    urlInfo,
    website
) {
    if (
        !openai ||
        !OPENAI_MODEL
    ) {
        return null;
    }

    const prompt = `
You are the website intelligence engine for SAFNEX NOVA.

Analyze ONLY the publicly visible information supplied below.

Do not claim:
- malware detection
- virus detection
- absolute safety
- trustworthiness that is not supported by evidence

Identify:
1. What type of website is this?
2. What does it contain?
3. What is it used for?

URL:
${urlInfo.raw}

Hostname:
${urlInfo.hostname}

Title:
${website.title}

Meta description:
${website.description}

Headings:
${JSON.stringify(website.headings)}

Visible text:
${website.text.substring(0, 12000)}

Return ONLY valid JSON:

{
  "name": "website or brand name",
  "type": "website type",
  "category": "main category",
  "purpose": "what the website is used for",
  "summary": "short explanation",
  "services": ["service 1", "service 2"],
  "language": "detected language",
  "confidence": "High | Medium | Low",
  "evidence": ["evidence 1", "evidence 2"]
}
`;

    try {
        const response =
            await openai.responses.create({
                model:
                    OPENAI_MODEL,

                input:
                    prompt
            });

        const output =
            response.output_text ||
            "";

        const cleaned =
            output
                .replace(
                    /^```json\s*/i,
                    ""
                )
                .replace(
                    /^```\s*/i,
                    ""
                )
                .replace(
                    /\s*```$/i,
                    ""
                )
                .trim();

        const parsed =
            JSON.parse(cleaned);

        return {
            name:
                parsed.name ||
                urlInfo.hostname,

            type:
                parsed.type ||
                "Website",

            category:
                parsed.category ||
                "General website",

            purpose:
                parsed.purpose ||
                "Public website information.",

            summary:
                parsed.summary ||
                "Website content analyzed.",

            services:
                Array.isArray(
                    parsed.services
                )
                    ? parsed.services
                    : [],

            language:
                parsed.language ||
                "Unknown",

            confidence:
                parsed.confidence ||
                "Medium",

            evidence:
                Array.isArray(
                    parsed.evidence
                )
                    ? parsed.evidence
                    : []
        };
    } catch (error) {
        console.error(
            "AI analysis failed:",
            error.message
        );

        return null;
    }
}

/* =========================================================
   SCORE EXPLANATION
========================================================= */

function buildScoreExplanation(
    security,
    knownService,
    fetchResult,
    fetchError,
    url
) {
    const reasons = [];

    const nonProduction =
        detectNonProductionDomain(
            url
        );

    const payment =
        detectPaymentSignals(
            url
        );

    if (
        nonProduction.length
    ) {
        reasons.push(
            "The hostname contains a test or non-production environment label: " +
                nonProduction.join(", ") +
                "."
        );
    }

    if (
        payment.paymentHits.length
    ) {
        reasons.push(
            "Payment-related wording was detected in the URL."
        );
    }

    if (
        payment.accountHits.length
    ) {
        reasons.push(
            "Account or verification wording was detected in the URL."
        );
    }

    if (knownService) {
        reasons.push(
            `The domain is recognized as ${knownService.name}.`
        );
    }

    if (fetchResult) {
        reasons.push(
            "The destination responded and could be inspected."
        );
    }

    if (fetchError) {
        reasons.push(
            "The destination could not be fetched, so its actual website content could not be fully verified."
        );
    }

    const dangerous =
        security.indicators.some(
            item =>
                item.type === "danger" ||
                item.type === "critical"
        );

    if (dangerous) {
        reasons.push(
            "One or more high-risk URL indicators affected the score."
        );
    }

    if (
        security.indicators.some(
            item =>
                item.title ===
                "HTTPS is enabled"
        )
    ) {
        reasons.push(
            "HTTPS is enabled, but HTTPS alone does not prove that the destination is safe."
        );
    }

    if (
        security.confidence ===
        "Low"
    ) {
        reasons.push(
            "Analysis confidence is low because the destination could not be sufficiently verified."
        );
    }

    if (!reasons.length) {
        reasons.push(
            "No major URL warning signals were detected."
        );
    }

    return reasons.join(" ");
}

/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    (req, res) => {
        res.json({
            ok: true,

            service:
                "SAFNEX NOVA Link Analyzer",

            version:
                "3.0",

            analyzer:
                "POST /api/analyze",

            aiConfigured:
                Boolean(
                    openai &&
                    OPENAI_MODEL
                )
        });
    }
);

/* =========================================================
   ANALYZER INFO
========================================================= */

app.get(
    "/api/analyze",
    (req, res) => {
        res.json({
            ok: true,

            message:
                "SAFNEX NOVA analyzer endpoint is online.",

            method:
                "POST",

            endpoint:
                "/api/analyze"
        });
    }
);

/* =========================================================
   MAIN ANALYZE API
========================================================= */

app.post(
    "/api/analyze",
    async (req, res) => {
        try {
            /* -----------------------------------------
               1. URL
            ----------------------------------------- */

            const rawUrl =
                normalizeUrl(
                    req.body?.url
                );

            /* -----------------------------------------
               2. PARSE
            ----------------------------------------- */

            const urlInfo =
                parseUrl(
                    rawUrl
                );

            const parsedUrl =
                new URL(
                    rawUrl
                );

            /* -----------------------------------------
               3. KNOWN SERVICE
            ----------------------------------------- */

            const knownService =
                detectKnownService(
                    parsedUrl
                );

            /* -----------------------------------------
               4. FETCH
            ----------------------------------------- */

            let fetchResult =
                null;

            let website =
                null;

            let intelligence =
                null;

            let fetchError =
                "";

            try {
                fetchResult =
                    await fetchWebsite(
                        rawUrl
                    );

                website =
                    extractWebsiteData(
                        fetchResult
                    );

                intelligence =
                    await understandWebsiteWithAI(
                        urlInfo,
                        website
                    );

                if (!intelligence) {
                    intelligence =
                        fallbackWebsiteUnderstanding(
                            urlInfo,
                            website,
                            knownService
                        );
                }
            } catch (error) {
                fetchError =
                    error.message;

                console.warn(
                    "Website fetch warning:",
                    error.message
                );

                if (knownService) {
                    intelligence =
                        fallbackWebsiteUnderstanding(
                            urlInfo,
                            null,
                            knownService
                        );
                }
            }

            /* -----------------------------------------
               5. SECURITY
            ----------------------------------------- */

            const security =
                analyzeSecurity(
                    rawUrl,
                    fetchResult,
                    knownService,
                    fetchError
                );

            /* -----------------------------------------
               6. WEBSITE DATA
            ----------------------------------------- */

            let websiteData;

            if (intelligence) {
                websiteData = {
                    ...intelligence,

                    httpStatus:
                        fetchResult?.status ??
                        "Unavailable",

                    contentType:
                        fetchResult?.contentType ??
                        "Unavailable",

                    status:
                        fetchResult
                            ? (
                                fetchResult.status >= 200 &&
                                fetchResult.status < 400
                                    ? "Reachable"
                                    : "Unreachable"
                            )
                            : "Unverified"
                };
            } else {
                websiteData = {
                    name:
                        "Website information unavailable",

                    type:
                        "Unknown / Unverified Website",

                    category:
                        "Not determined",

                    purpose:
                        "The destination could not be fetched, so the actual website content could not be confirmed.",

                    summary:
                        "The URL structure was analyzed, but the website itself could not be verified.",

                    services: [],

                    language:
                        "Not determined",

                    confidence:
                        "Low",

                    evidence: [],

                    httpStatus:
                        "Unavailable",

                    contentType:
                        "Unavailable",

                    status:
                        "Unverified"
                };
            }

            /* -----------------------------------------
               7. CONTENT
            ----------------------------------------- */

            let content;

            if (website) {
                content = {
                    title:
                        website.title,

                    description:
                        website.description,

                    headings:
                        website.headings,

                    visibleText:
                        website.text,

                    textLength:
                        website.textLength,

                    links:
                        website.links,

                    linkCount:
                        website.links.length,

                    images:
                        website.images,

                    imageCount:
                        website.images.length
                };
            } else if (knownService) {
                content = {
                    title:
                        knownService.name,

                    description:
                        knownService.contentDescription,

                    headings: [],

                    visibleText:
                        "",

                    textLength:
                        0,

                    links: [],

                    linkCount:
                        0,

                    images: [],

                    imageCount:
                        0
                };
            } else {
                content = {
                    title:
                        "Unavailable",

                    description:
                        "Website content could not be verified.",

                    headings: [],

                    visibleText:
                        "",

                    textLength:
                        0,

                    links: [],

                    linkCount:
                        0,

                    images: [],

                    imageCount:
                        0
                };
            }

            /* -----------------------------------------
               8. THREE QUESTIONS
            ----------------------------------------- */

            const questions = {
                websiteType:
                    websiteData.type,

                websiteContent:
                    knownService
                        ? knownService.contentDescription
                        : website
                            ? (
                                website.description ||
                                website.title ||
                                "Public website content was retrieved and analyzed."
                            )
                            : "The website content could not be retrieved, so the actual contents cannot be confirmed.",

                whyScore:
                    buildScoreExplanation(
                        security,
                        knownService,
                        fetchResult,
                        fetchError,
                        parsedUrl
                    )
            };

            /* -----------------------------------------
               9. FINAL RESPONSE
            ----------------------------------------- */

            return res.json({
                ok: true,

                securityScore:
                    security.score,

                riskScore:
                    security.riskScore,

                verdict:
                    security.verdict,

                riskLevel:
                    security.riskLevel,

                confidence:
                    security.confidence,

                knownPhishing:
                    security.knownPhishing,

                knownService:
                    knownService
                        ? {
                            name:
                                knownService.name,

                            provider:
                                knownService.provider,

                            type:
                                knownService.type,

                            official:
                                knownService.official
                        }
                        : null,

                url:
                    urlInfo,

                finalUrl:
                    fetchResult?.finalUrl ||
                    rawUrl,

                website:
                    websiteData,

                security: {
                    score:
                        security.score,

                    riskScore:
                        security.riskScore,

                    verdict:
                        security.verdict,

                    riskLevel:
                        security.riskLevel,

                    confidence:
                        security.confidence,

                    knownPhishing:
                        security.knownPhishing,

                    indicators:
                        security.indicators,

                    verification:
                        security.verification,

                    malwareReputation:
                        security.malwareReputation,

                    redirects:
                        fetchResult?.redirects ||
                        []
                },

                content,

                questions,

                analysis: {
                    aiEnabled:
                        Boolean(
                            openai &&
                            OPENAI_MODEL
                        ),

                    websiteUnderstanding:
                        fetchResult
                            ? "Website intelligence is based on publicly accessible page content when reachable."
                            : knownService
                                ? "The service was identified from its domain, but the actual page contents were not fetched."
                                : "The website could not be verified.",

                    securityNote:
                        "The security score is a risk-signal score, not a guarantee of safety. HTTPS, a known service, or normal-looking content alone do not prove that a specific URL is safe."
                }
            });
        } catch (error) {
            console.error(
                "ANALYSIS ERROR:",
                error
            );

            return res
                .status(400)
                .json({
                    ok: false,

                    error:
                        error?.message ||
                        "Analysis failed."
                });
        }
    }
);

/* =========================================================
   API 404
========================================================= */

app.use(
    "/api",
    (req, res) => {
        res
            .status(404)
            .json({
                ok: false,

                error:
                    "API endpoint not found."
            });
    }
);

/* =========================================================
   GENERAL ERROR
========================================================= */

app.use(
    (err, req, res, next) => {
        console.error(
            "SERVER ERROR:",
            err
        );

        res
            .status(500)
            .json({
                ok: false,

                error:
                    "Internal server error."
            });
    }
);

/* =========================================================
   START
========================================================= */
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(
    PORT,
    () => {
        console.log(
            "=============================================="
        );

        console.log(
            "SAFNEX NOVA LINK ANALYZER"
        );

        console.log(
            "=============================================="
        );

        console.log(
            `Server: http://localhost:${PORT}`
        );

        console.log(
            `Health: http://localhost:${PORT}/api/health`
        );

        console.log(
            `Analyze: POST http://localhost:${PORT}/api/analyze`
        );

        console.log(
            `AI configured: ${Boolean(
                openai &&
                OPENAI_MODEL
            )}`
        );

        console.log(
            "=============================================="
        );
    }
);