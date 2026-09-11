import express from "express";
import cors from "cors";

import dotenv from "dotenv";
import dns from "node:dns/promises";
import net from "node:net";
import { createWorker } from "tesseract.js";
import { MongoClient } from "mongodb";
import { parsePhoneNumberFromString } from "libphonenumber-js/max";

dotenv.config();
import multer from "multer";

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 8 * 1024 * 1024
    }
});
/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(
    process.env.PORT ||
    process.env.MESSAGE_PORT ||
    3000
);

const MONGODB_URI =
    process.env.MONGODB_URI || "";

const MONGODB_DATABASE =
    process.env.MONGODB_DATABASE ||
    "safnex_nova";

const MONGODB_COLLECTION =
    process.env.MONGODB_COLLECTION ||
    "trai_sms_headers.xlsx";

const OCR_LANGUAGE =
    process.env.OCR_LANGUAGE ||
    "eng";

/* =========================================================
   EXPRESS
========================================================= */

const app = express();
app.use(express.static('.'));
app.use(cors());

app.use(
    express.json({
        limit: "15mb"
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "15mb"
    })
);

/* =========================================================
   GLOBAL SERVICES
========================================================= */

let ocrWorker = null;
let ocrReady = false;

let mongoClient = null;
let mongoDatabase = null;
let traiCollection = null;
let mongoReady = false;
let traiDocuments = 0;

/* =========================================================
   COMMON HELPERS
========================================================= */

function cleanText(text) {
    return String(text || "")
        .replace(/\r/g, "")
        .replace(/[ \t]+/g, " ")
        .replace(/\n{3,}/g, "\n\n")
        .trim();
}

function unique(values) {
    return [
        ...new Set(
            values
                .map(value =>
                    String(value || "").trim()
                )
                .filter(Boolean)
        )
    ];
}

function escapeRegex(value) {
    return String(value || "")
        .replace(
            /[.*+?^${}()|[\]\\]/g,
            "\\$&"
        );
}

/* =========================================================
   BASE64 IMAGE
========================================================= */

function extractBase64Image(input) {

    if (!input) {
        return null;
    }

    let value =
        String(input).trim();

    if (
        value.startsWith(
            "data:image/"
        )
    ) {
        const comma =
            value.indexOf(",");

        if (comma === -1) {
            return null;
        }

        value =
            value.substring(
                comma + 1
            );
    }

    value =
        value.replace(
            /\s/g,
            ""
        );

    if (!value) {
        return null;
    }

    if (
        !/^[A-Za-z0-9+/=_-]+$/.test(
            value
        )
    ) {
        return null;
    }

    try {

        return Buffer.from(
            value,
            "base64"
        );

    } catch {

        return null;

    }
}

/* =========================================================
   LINK ANALYZER
========================================================= */

function normalizeUrl(value) {

    let url =
        String(value || "")
            .trim();

    if (!url) {
        throw new Error(
            "URL is required."
        );
    }

    if (
        !/^https?:\/\//i.test(url)
    ) {
        url =
            "https://" + url;
    }

    return url;
}

function parseUrl(url) {

    const parsed =
        new URL(url);

    return {
        href: parsed.href,
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        host: parsed.host,
        pathname: parsed.pathname,
        search: parsed.search,
        hash: parsed.hash,
        port: parsed.port || "",
        origin: parsed.origin
    };
}

function getRootDomain(hostname) {

    const host =
        String(hostname || "")
            .toLowerCase();

    const parts =
        host.split(".")
            .filter(Boolean);

    if (parts.length <= 2) {
        return host;
    }

    return parts
        .slice(-2)
        .join(".");
}

function isPrivateIPv4(hostname) {

    if (
        !net.isIPv4(hostname)
    ) {
        return false;
    }

    const parts =
        hostname
            .split(".")
            .map(Number);

    const [a, b] = parts;

    if (a === 10) {
        return true;
    }

    if (
        a === 172 &&
        b >= 16 &&
        b <= 31
    ) {
        return true;
    }

    if (a === 192 && b === 168) {
        return true;
    }

    if (a === 127) {
        return true;
    }

    if (a === 169 && b === 254) {
        return true;
    }

    if (a === 0) {
        return true;
    }

    return false;
}

function isPrivateIPv6(hostname) {

    if (
        !net.isIPv6(hostname)
    ) {
        return false;
    }

    const value =
        hostname.toLowerCase();

    return (
        value === "::1" ||
        value.startsWith("fc") ||
        value.startsWith("fd") ||
        value.startsWith("fe80")
    );
}

function isBlockedHost(hostname) {

    const host =
        String(hostname || "")
            .toLowerCase();

    if (
        host === "localhost" ||
        host.endsWith(".localhost")
    ) {
        return true;
    }

    if (isPrivateIPv4(host)) {
        return true;
    }

    if (isPrivateIPv6(host)) {
        return true;
    }

    return false;
}

/* =========================================================
   KNOWN SERVICES
========================================================= */

const KNOWN_SERVICES = [

    {
        domains: [
            "google.com",
            "google.co.in"
        ],
        name: "Google"
    },

    {
        domains: [
            "youtube.com",
            "youtu.be"
        ],
        name: "YouTube"
    },

    {
        domains: [
            "facebook.com",
            "fb.com"
        ],
        name: "Facebook"
    },

    {
        domains: [
            "instagram.com"
        ],
        name: "Instagram"
    },

    {
        domains: [
            "whatsapp.com",
            "wa.me"
        ],
        name: "WhatsApp"
    },

    {
        domains: [
            "amazon.in",
            "amazon.com"
        ],
        name: "Amazon"
    },

    {
        domains: [
            "microsoft.com"
        ],
        name: "Microsoft"
    },

    {
        domains: [
            "apple.com"
        ],
        name: "Apple"
    },

    {
        domains: [
            "paytm.com"
        ],
        name: "Paytm"
    },

    {
        domains: [
            "phonepe.com"
        ],
        name: "PhonePe"
    },

    {
        domains: [
            "sbi.co.in"
        ],
        name: "SBI"
    },

    {
        domains: [
            "hdfcbank.com"
        ],
        name: "HDFC Bank"
    },

    {
        domains: [
            "icicibank.com"
        ],
        name: "ICICI Bank"
    }

];

function detectKnownService(parsed) {

    const hostname =
        parsed.hostname
            .toLowerCase();

    const root =
        getRootDomain(hostname);

    for (
        const service
        of KNOWN_SERVICES
    ) {

        for (
            const domain
            of service.domains
        ) {

            if (
                root === domain ||
                hostname === domain ||
                hostname.endsWith(
                    "." + domain
                )
            ) {
                return service;
            }

        }

    }

    return null;
}

/* =========================================================
   LINK SECURITY
========================================================= */

function analyzeLinkSecurity(
    url,
    parsed,
    knownService,
    fetchResult,
    fetchError
) {

    const indicators = [];
    let riskScore = 0;

    /* HTTPS */

    if (
        parsed.protocol === "https:"
    ) {

        indicators.push({
            type: "positive",
            title: "HTTPS is enabled",
            message:
                "The link uses encrypted HTTPS."
        });

    } else {

        riskScore += 20;

        indicators.push({
            type: "warning",
            title: "HTTPS is not enabled",
            message:
                "The link does not use HTTPS."
        });

    }

    /* IP ADDRESS */

    if (
        net.isIP(
            parsed.hostname
        )
    ) {

        riskScore += 25;

        indicators.push({
            type: "danger",
            title: "IP address used",
            message:
                "The link uses an IP address instead of a normal domain."
        });

    }

    /* PRIVATE HOST */

    if (
        isBlockedHost(
            parsed.hostname
        )
    ) {

        riskScore += 40;

        indicators.push({
            type: "critical",
            title: "Private or local destination",
            message:
                "The destination points to a private or local network address."
        });

    }

    /* URL LENGTH */

    if (
        url.length > 180
    ) {

        riskScore += 10;

        indicators.push({
            type: "warning",
            title: "Very long URL",
            message:
                "The URL is unusually long."
        });

    }

    /* @ SYMBOL */

    if (
        parsed.href.includes("@")
    ) {

        riskScore += 20;

        indicators.push({
            type: "danger",
            title: "Suspicious @ symbol",
            message:
                "The URL contains an @ symbol that can be used to confuse users."
        });

    }

    /* MANY SUBDOMAINS */

    const dotCount =
        parsed.hostname
            .split(".")
            .length - 1;

    if (
        dotCount >= 4
    ) {

        riskScore += 10;

        indicators.push({
            type: "warning",
            title: "Many subdomains",
            message:
                "The hostname contains many domain levels."
        });

    }

    /* SUSPICIOUS WORDS */

    const suspiciousWords = [
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "wallet",
        "payment",
        "claim",
        "reward",
        "bonus",
        "gift",
        "otp",
        "bank",
        "signin",
        "confirm"
    ];

    const urlLower =
        url.toLowerCase();

    const matchedWords =
        suspiciousWords.filter(
            word =>
                urlLower.includes(word)
        );

    if (
        matchedWords.length
    ) {

        riskScore += Math.min(
            matchedWords.length * 5,
            20
        );

        indicators.push({
            type: "warning",
            title: "Sensitive URL wording",
            message:
                `The URL contains sensitive wording: ${matchedWords.join(", ")}.`
        });

    }

    /* KNOWN SERVICE */

    if (knownService) {

        indicators.push({
            type: "positive",
            title: "Recognized website",
            message:
                `The domain is recognized as ${knownService.name}.`
        });

    }

    /* FETCH */

    if (fetchResult) {

        indicators.push({
            type: "positive",
            title: "Website responded",
            message:
                `The destination responded with HTTP ${fetchResult.status}.`
        });

    }

    if (fetchError) {

        indicators.push({
            type: "warning",
            title: "Website content could not be verified",
            message:
                "The destination could not be fully inspected."
        });

    }

    riskScore =
        Math.max(
            0,
            Math.min(
                100,
                riskScore
            )
        );

    const securityScore =
        100 - riskScore;

    let verdict;

    if (
        securityScore >= 85
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

    let riskLevel;

    if (
        riskScore >= 70
    ) {

        riskLevel = "HIGH RISK";

    } else if (
        riskScore >= 35
    ) {

        riskLevel = "MEDIUM RISK";

    } else {

        riskLevel = "LOW RISK";

    }

    return {
        securityScore,
        riskScore,
        verdict,
        riskLevel,
        confidence:
            fetchResult
                ? "High"
                : "Medium",
        indicators
    };
}

/* =========================================================
   FETCH WEBSITE
========================================================= */

async function fetchWebsite(url) {

    const parsed =
        new URL(url);

    if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
    ) {

        throw new Error(
            "Only HTTP and HTTPS URLs are supported."
        );

    }

    if (
        isBlockedHost(
            parsed.hostname
        )
    ) {

        throw new Error(
            "Blocked private or local destination."
        );

    }

    const controller =
        new AbortController();

    const timer =
        setTimeout(
            () => controller.abort(),
            10000
        );

    try {

        const response =
            await fetch(
                url,
                {
                    method: "GET",
                    redirect: "manual",
                    signal:
                        controller.signal,
                    headers: {
                        "User-Agent":
                            "SAFNEX-NOVA-Security-Analyzer/1.0",
                        "Accept":
                            "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8"
                    }
                }
            );

        const contentType =
            response.headers.get(
                "content-type"
            ) || "";

        let body = "";

        if (
            contentType.includes(
                "text"
            ) ||
            contentType.includes(
                "html"
            )
        ) {

            body =
                await response.text();

            body =
                body.substring(
                    0,
                    500000
                );

        }

        return {
            status:
                response.status,

            statusText:
                response.statusText,

            contentType,

            body,

            location:
                response.headers.get(
                    "location"
                ) || ""
        };

    } finally {

        clearTimeout(timer);

    }
}

/* =========================================================
   WEBSITE INFORMATION
========================================================= */

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
            /<[^>]+>/g,
            " "
        )
        .replace(
            /\s+/g,
            " "
        )
        .trim();

}

function extractTitle(html) {

    const match =
        String(html || "")
            .match(
                /<title[^>]*>([\s\S]*?)<\/title>/i
            );

    return match
        ? cleanText(
            match[1]
        )
        : "";

}

function extractMetaDescription(
    html
) {

    const match =
        String(html || "")
            .match(
                /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i
            );

    return match
        ? cleanText(
            match[1]
        )
        : "";

}

function extractHeadings(html) {

    const matches =
        String(html || "")
            .match(
                /<h[1-3][^>]*>[\s\S]*?<\/h[1-3]>/gi
            ) || [];

    return unique(
        matches.map(
            item =>
                stripHtml(item)
        )
    ).slice(0, 10);

}

function extractPageUrls(
    html
) {

    const matches =
        String(html || "")
            .match(
                /https?:\/\/[^\s"'<>]+/gi
            ) || [];

    return unique(
        matches
    ).slice(0, 20);

}

function understandWebsite(
    parsed,
    fetchResult,
    knownService
) {

    const html =
        fetchResult?.body || "";

    const title =
        extractTitle(html);

    const description =
        extractMetaDescription(
            html
        );

    const headings =
        extractHeadings(html);

    const plainText =
        stripHtml(html)
            .substring(
                0,
                3000
            );

    if (knownService) {

        return {
            name:
                title ||
                knownService.name,

            type:
                `${knownService.name} Website`,

            category:
                knownService.name,

            purpose:
                description ||
                `This appears to be the official or recognized ${knownService.name} website.`,

            contentSummary:
                headings.length
                    ? headings.join(
                        " • "
                    )
                    : plainText,

            headings,

            detectedLinks:
                extractPageUrls(
                    html
                )
        };

    }

    let type =
        "General Website";

    const lower =
        (
            title +
            " " +
            description +
            " " +
            plainText
        ).toLowerCase();

    if (
        /bank|banking|finance|loan|credit/.test(
            lower
        )
    ) {

        type =
            "Banking / Financial Website";

    } else if (
        /shop|cart|product|buy|price|order/.test(
            lower
        )
    ) {

        type =
            "Shopping / E-commerce Website";

    } else if (
        /news|article|breaking|journal/.test(
            lower
        )
    ) {

        type =
            "News / Information Website";

    } else if (
        /school|college|university|education|course/.test(
            lower
        )
    ) {

        type =
            "Education Website";

    } else if (
        /government|gov\.in|official/.test(
            lower
        )
    ) {

        type =
            "Government / Public Service Website";

    }

    return {

        name:
            title ||
            parsed.hostname,

        type,

        category:
            type,

        purpose:
            description ||
            `This website appears to be a ${type.toLowerCase()}.`,

        contentSummary:
            headings.length
                ? headings.join(
                    " • "
                )
                : plainText,

        headings,

        detectedLinks:
            extractPageUrls(
                html
            )

    };

}

/* =========================================================
   LINK API
========================================================= */

app.get(
    "/api/analyze",
    (req, res) => {

        res.json({
            ok: true,

            message:
                "SAFNEX NOVA LINK analyzer is online.",

            method:
                "POST",

            endpoint:
                "/api/analyze",

            engine:
                "rule-based",

            cost:
                "FREE"

        });

    }
);

        

        // Accept multipart file
      
/* =========================================================
   PHONE ANALYZER
========================================================= */

const COUNTRY_NAMES = {

    IN: "India",
    US: "United States",
    GB: "United Kingdom",
    AE: "United Arab Emirates",
    SG: "Singapore",
    AU: "Australia",
    CA: "Canada",
    MY: "Malaysia",
    LK: "Sri Lanka"

};

function normalizePhoneInput(
    value
) {

    return String(
        value || ""
    )
        .trim()
        .replace(
            /[^\d+]/g,
            ""
        );

}

function maskPhoneNumber(
    value
) {

    const digits =
        String(value || "")
            .replace(
                /\D/g,
                ""
            );

    if (
        digits.length <= 4
    ) {
        return digits;
    }

    return (
        "*".repeat(
            Math.max(
                0,
                digits.length - 4
            )
        ) +
        digits.slice(-4)
    );

}

function analyzePhone(
    input,
    country
) {

    const raw =
        normalizePhoneInput(
            input
        );

    if (!raw) {

        return {
            valid: false,
            securityScore: 0,
            riskScore: 100,
            verdict: "Invalid",
            riskLevel: "HIGH RISK",
            confidence: "High",
            reason:
                "No phone number was provided."
        };

    }

    let parsed =
        null;

    try {

        parsed =
            parsePhoneNumberFromString(
                raw,
                country || "IN"
            );

    } catch {

        parsed =
            null;

    }

    if (!parsed) {

        return {

            valid: false,

            securityScore: 15,

            riskScore: 85,

            verdict:
                "Invalid / Unrecognized",

            riskLevel:
                "HIGH RISK",

            confidence:
                "High",

            phone:
                maskPhoneNumber(
                    raw
                ),

            reason:
                "The number could not be validated using the phone numbering rules."

        };

    }

    const possible =
        parsed.isPossible();

    const valid =
        parsed.isValid();

    const type =
        parsed.getType?.() ||
        "UNKNOWN";

    let securityScore =
        valid
            ? 85
            : possible
                ? 65
                : 25;

    if (
        type === "FIXED_LINE"
    ) {
        securityScore =
            Math.min(
                securityScore + 3,
                95
            );
    }

    const riskScore =
        100 -
        securityScore;

    let verdict;

    if (
        valid
    ) {

        verdict =
            "Likely Valid";

    } else if (
        possible
    ) {

        verdict =
            "Possible";

    } else {

        verdict =
            "Invalid";

    }

    let riskLevel;

    if (
        riskScore >= 70
    ) {

        riskLevel =
            "HIGH RISK";

    } else if (
        riskScore >= 35
    ) {

        riskLevel =
            "MEDIUM RISK";

    } else {

        riskLevel =
            "LOW RISK";

    }

    return {

        valid,

        possible,

        securityScore,

        riskScore,

        verdict,

        riskLevel,

        confidence:
            "High",

        phone:
            maskPhoneNumber(
                raw
            ),

        country:
            parsed.country || "",

        countryName:
            COUNTRY_NAMES[
                parsed.country
            ] ||
            parsed.country ||
            "",

        callingCode:
            parsed.countryCallingCode
                ? `+${parsed.countryCallingCode}`
                : "",

        nationalNumber:
            parsed.nationalNumber ||
            "",

        internationalFormat:
            parsed.formatInternational(),

        nationalFormat:
            parsed.formatNational(),

        type,

        reason:
            valid
                ? "The number matches the numbering rules for the selected country."
                : possible
                    ? "The number has a possible structure but could not be confirmed as valid."
                    : "The number does not match the expected numbering rules."

    };

}

app.get(
    "/api/phone-check",
    (req, res) => {

        res.json({

            ok: true,

            endpoint:
                "POST /api/phone-check",

            message:
                "Send a JSON body containing phone and optional country.",

            example: {
                phone:
                    "+919876543210",
                country:
                    "IN"
            },

            engine:
                "libphonenumber-js",

            cost:
                "FREE"

        });

    }
);

app.post(
    "/api/phone-check",
    (req, res) => {

        try {

            const result =
                analyzePhone(
                    req.body?.phone,
                    req.body?.country ||
                    "IN"
                );

            return res.json({

                ok: true,

                result,

                analysis: {

                    engine:
                        "libphonenumber-js",

                    aiEnabled:
                        false,

                    cost:
                        "FREE"

                }

            });

        } catch (error) {

            return res.status(400).json({

                ok: false,

                error:
                    "PHONE_ANALYSIS_ERROR",

                message:
                    error.message

            });

        }

    }
);

app.post(
    "/api/phone-validate",
    (req, res) => {

        try {

            const result =
                analyzePhone(
                    req.body?.phone,
                    req.body?.country ||
                    "IN"
                );

            return res.json({

                ok: true,

                valid:
                    result.valid,

                possible:
                    result.possible,

                country:
                    result.country,

                countryName:
                    result.countryName,

                internationalFormat:
                    result.internationalFormat,

                nationalFormat:
                    result.nationalFormat,

                type:
                    result.type,

                reason:
                    result.reason,

                engine:
                    "libphonenumber-js",

                cost:
                    "FREE"

            });

        } catch (error) {

            return res.status(400).json({

                ok: false,

                error:
                    "PHONE_VALIDATION_ERROR",

                message:
                    error.message

            });

        }

    }
);

/* =========================================================
   MESSAGE / TRAI
========================================================= */

function normalizeTRAIHeader(
    value
) {

    const input =
        String(value || "")
            .trim()
            .toUpperCase();

    if (!input) {

        return {

            senderId: "",
            routingPrefix: "",
            baseHeader: "",
            category: ""

        };

    }

    const parts =
        input.split("-");

    /* XY-ABCDEF-P */

    if (
        parts.length === 3 &&
        /^[A-Z]{2}$/.test(
            parts[0]
        ) &&
        /^[A-Z0-9]{2,11}$/.test(
            parts[1]
        ) &&
        /^[PST]$/.test(
            parts[2]
        )
    ) {

        return {

            senderId:
                input,

            routingPrefix:
                parts[0],

            baseHeader:
                parts[1],

            category:
                parts[2]

        };

    }

    /* XY-ABCDEF */

    if (
        parts.length === 2 &&
        /^[A-Z]{2}$/.test(
            parts[0]
        ) &&
        /^[A-Z0-9]{2,11}$/.test(
            parts[1]
        )
    ) {

        return {

            senderId:
                input,

            routingPrefix:
                parts[0],

            baseHeader:
                parts[1],

            category:
                ""

        };

    }

    /* ABCDEF-P */

    if (
        parts.length === 2 &&
        /^[A-Z0-9]{2,11}$/.test(
            parts[0]
        ) &&
        /^[PST]$/.test(
            parts[1]
        )
    ) {

        return {

            senderId:
                input,

            routingPrefix:
                "",

            baseHeader:
                parts[0],

            category:
                parts[1]

        };

    }

    /* ABCDEF */

    if (
        /^[A-Z0-9]{2,11}$/.test(
            input
        )
    ) {

        return {

            senderId:
                input,

            routingPrefix:
                "",

            baseHeader:
                input,

            category:
                ""

        };

    }

    return {

        senderId:
            input,

        routingPrefix:
            "",

        baseHeader:
            "",

        category:
            ""

    };

}

/* =========================================================
   TRAI HEADER EXTRACTION
========================================================= */

function extractTRAIHeaders(
    text
) {

    const results = [];

    const pattern =
        /\b[A-Z]{2}-[A-Z0-9]{2,11}(?:-[PST])?\b/gi;

    const matches =
        text.match(
            pattern
        ) || [];

    for (
        const match
        of matches
    ) {

        const normalized =
            normalizeTRAIHeader(
                match
            );

        if (
            normalized.baseHeader
        ) {

            results.push(
                normalized
            );

        }

    }

    return results;

}

/* =========================================================
   STANDALONE POSSIBLE HEADER
========================================================= */

function extractStandaloneHeaders(
    text
) {

    const results = [];

    const pattern =
        /\b[A-Z][A-Z0-9]{2,10}\b/g;

    const matches =
        text.match(
            pattern
        ) || [];

    const ignored =
        new Set([

            "THE",
            "AND",
            "FOR",
            "YOU",
            "YOUR",
            "TODAY",
            "THIS",
            "THAT",
            "WITH",
            "FROM",
            "NOW",
            "CONGRATS",
            "SELECTED",
            "ENJOY",
            "REWARDS",
            "AVAIL",
            "TATA",
            "NEU",
            "TERMS",
            "HTTPS",
            "HTTP",
            "SMS",
            "OTP",
            "AM",
            "PM",
            "JOINING",
            "FEE"

        ]);

    for (
        const match
        of matches
    ) {

        const value =
            match.toUpperCase();

        if (
            ignored.has(
                value
            )
        ) {
            continue;
        }

        if (
            value.length >= 3 &&
            value.length <= 11
        ) {

            results.push(
                normalizeTRAIHeader(
                    value
                )
            );

        }

    }

    return results;

}

/* =========================================================
   SENDER INFO
========================================================= */

function extractSenderInfo(
    text
) {

    const exact =
        extractTRAIHeaders(
            text
        );

    if (
        exact.length
    ) {

        const primary =
            exact[0];

        return {

            senderId:
                primary.senderId,

            senderIds:
                unique(
                    exact.map(
                        item =>
                            item.senderId
                    )
                ),

            routingPrefix:
                primary.routingPrefix,

            baseHeader:
                primary.baseHeader,

            category:
                primary.category,

            senderIdType:
                "TRAI_SMS_HEADER",

            senderIdConfidence:
                "High"

        };

    }

    const standalone =
        extractStandaloneHeaders(
            text
        );

    if (
        standalone.length
    ) {

        const primary =
            standalone[0];

        return {

            senderId:
                primary.senderId,

            senderIds:
                unique(
                    standalone.map(
                        item =>
                            item.senderId
                    )
                ),

            routingPrefix:
                primary.routingPrefix,

            baseHeader:
                primary.baseHeader,

            category:
                primary.category,

            senderIdType:
                "POSSIBLE_SMS_HEADER",

            senderIdConfidence:
                "Medium"

        };

    }

    return {

        senderId:
            "",

        senderIds:
            [],

        routingPrefix:
            "",

        baseHeader:
            "",

        category:
            "",

        senderIdType:
            "NOT_FOUND",

        senderIdConfidence:
            "Low"

    };

}

/* =========================================================
   TRAI DATABASE VERIFICATION
========================================================= */

async function verifyTRAIHeader(
    senderInfo
) {

    if (
        !senderInfo.baseHeader
    ) {

        return {

            status:
                "SENDER_ID_NOT_FOUND",

            verified:
                false,

            found:
                false,

            source:
                "TRAI_OFFICIAL_DATASET",

            principalEntityName:
                "",

            matchedHeader:
                "",

            message:
                "No usable sender ID was extracted from the screenshot."

        };

    }

    if (
        !mongoReady ||
        !traiCollection
    ) {

        return {

            status:
                "NOT_VERIFIED",

            verified:
                false,

            found:
                false,

            source:
                "TRAI_OFFICIAL_DATASET",

            principalEntityName:
                "",

            matchedHeader:
                "",

            message:
                "The official TRAI dataset is currently unavailable for verification."

        };

    }

    try {

        const baseHeader =
            senderInfo.baseHeader
                .toUpperCase()
                .trim();

        let document =
            await traiCollection.findOne(
                {
                    Header:
                        baseHeader
                }
            );

        if (!document) {

            document =
                await traiCollection.findOne(
                    {
                        Header: {
                            $regex:
                                `^${escapeRegex(baseHeader)}$`,
                            $options:
                                "i"
                        }
                    }
                );

        }

        if (document) {

            const entity =
                document[
                    "Principal Entity Name"
                ] ||
                document[
                    "PrincipalEntityName"
                ] ||
                document[
                    "Principal Entity"
                ] ||
                "";

            return {

                status:
                    "REGISTERED",

                verified:
                    true,

                found:
                    true,

                source:
                    "TRAI_OFFICIAL_DATASET",

                principalEntityName:
                    String(
                        entity
                    ).trim(),

                matchedHeader:
                    String(
                        document.Header ||
                        baseHeader
                    ).trim(),

                message:
                    "Sender header found in the official TRAI dataset."

            };

        }

        return {

            status:
                "NOT_VERIFIED",

            verified:
                false,

            found:
                false,

            source:
                "TRAI_OFFICIAL_DATASET",

            principalEntityName:
                "",

            matchedHeader:
                "",

            message:
                "Sender header was not found in the official TRAI dataset. This does not by itself prove that the message is fake."

        };

    } catch (error) {

        console.error(
            "TRAI verification error:",
            error.message
        );

        return {

            status:
                "NOT_VERIFIED",

            verified:
                false,

            found:
                false,

            source:
                "TRAI_OFFICIAL_DATASET",

            principalEntityName:
                "",

            matchedHeader:
                "",

            message:
                "TRAI verification could not be completed."

        };

    }

}

/* =========================================================
   MESSAGE URL EXTRACTION
========================================================= */

function repairOCRUrls(
    text
) {

    return String(text || "")
        .replace(
            /(https?:\/\/[^\s]+)\s*\n\s*([^\s]+)/gi,
            "$1$2"
        )
        .replace(
            /(www\.[^\s]+)\s*\n\s*([^\s]+)/gi,
            "$1$2"
        );

}

function extractMessageUrls(
    text
) {

    const repaired =
        repairOCRUrls(
            text
        );

    const matches =
        repaired.match(
            /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi
        ) || [];

    return unique(
        matches.map(
            url =>
                url.replace(
                    /[),.;!?]+$/g,
                    ""
                )
        )
    ).slice(0, 20);

}

/* =========================================================
   PHONE / EMAIL EXTRACTION
========================================================= */

function extractMessagePhones(
    text
) {

    const matches =
        text.match(
            /(?:\+?\d[\d\s().-]{7,}\d)/g
        ) || [];

    return unique(
        matches.map(
            number =>
                number
                    .replace(
                        /[^\d+]/g,
                        ""
                    )
                    .trim()
        )
    ).slice(0, 20);

}

function extractMessageEmails(
    text
) {

    const matches =
        text.match(
            /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
        ) || [];

    return unique(
        matches
    ).slice(0, 20);

}

function extractDomains(
    urls
) {

    const domains = [];

    for (
        const url
        of urls
    ) {

        try {

            const normalized =
                url.startsWith(
                    "http"
                )
                    ? url
                    : `https://${url}`;

            const parsed =
                new URL(
                    normalized
                );

            domains.push(
                parsed.hostname
            );

        } catch {

            // ignore

        }

    }

    return unique(
        domains
    );

}

/* =========================================================
   ORGANIZATIONS
========================================================= */

const ORGANIZATIONS = [

    "Tata Neu",
    "Airtel",
    "Jio",
    "Vi",
    "Vodafone",
    "Idea",
    "Google",
    "Microsoft",
    "Amazon",
    "Flipkart",
    "Paytm",
    "PhonePe",
    "Google Pay",
    "HDFC Bank",
    "ICICI Bank",
    "SBI",
    "State Bank of India",
    "Axis Bank",
    "Kotak",
    "Canara Bank",
    "UIDAI",
    "Aadhaar",
    "TRAI",
    "IRCTC"

];

function extractOrganizations(
    text
) {

    const found = [];

    const lower =
        text.toLowerCase();

    for (
        const organization
        of ORGANIZATIONS
    ) {

        if (
            lower.includes(
                organization.toLowerCase()
            )
        ) {

            found.push(
                organization
            );

        }

    }

    return unique(
        found
    );

}

/* =========================================================
   SENSITIVE REQUESTS
========================================================= */

function detectSensitiveRequests(
    text
) {

    const patterns = [

        {
            label:
                "OTP",

            regex:
                /\botp\b|\bone[- ]time password\b/i
        },

        {
            label:
                "Password",

            regex:
                /\bpassword\b|\bpasscode\b/i
        },

        {
            label:
                "Bank details",

            regex:
                /\bbank account\b|\baccount number\b|\bifsc\b/i
        },

        {
            label:
                "Card details",

            regex:
                /\bcredit card\b|\bdebit card\b|\bcard number\b|\bcvv\b/i
        },

        {
            label:
                "UPI",

            regex:
                /\bupi\b|\bupi id\b/i
        },

        {
            label:
                "Aadhaar",

            regex:
                /\baadhaar\b|\baadhar\b/i
        },

        {
            label:
                "Payment",

            regex:
                /\bpayment\b|\bpay now\b|\btransfer money\b/i
        }

    ];

    return patterns
        .filter(
            item =>
                item.regex.test(
                    text
                )
        )
        .map(
            item =>
                item.label
        );

}

/* =========================================================
   SUSPICIOUS MESSAGE INDICATORS
========================================================= */

function detectSuspiciousIndicators(
    text,
    urls
) {

    const indicators = [];

    if (
        /\bclick here\b|\bclick the link\b|\btap here\b/i
            .test(text)
    ) {

        indicators.push(
            "Urgent link/click instruction"
        );

    }

    if (
        /\bverify your account\b|\bverify immediately\b|\bverify now\b/i
            .test(text)
    ) {

        indicators.push(
            "Account verification request"
        );

    }

    if (
        /\bclaim now\b|\bclaim your reward\b|\bwon\b|\bselected\b|\bcongratulations\b/i
            .test(text)
    ) {

        indicators.push(
            "Reward or selection claim"
        );

    }

    if (
        /\bexpires today\b|\bexpire soon\b|\blimited time\b|\bact now\b/i
            .test(text)
    ) {

        indicators.push(
            "Time-pressure language"
        );

    }

    if (
        /\bdo not share\b.*\botp\b/i
            .test(text)
    ) {

        indicators.push(
            "OTP-related message"
        );

    }

    if (
        urls.length > 0
    ) {

        indicators.push(
            "Message contains a web link"
        );

    }

    return unique(
        indicators
    );

}

/* =========================================================
   PLATFORM DETECTION
========================================================= */

function detectPlatform(
    text,
    senderInfo
) {

    const lower =
        text.toLowerCase();

    if (
        senderInfo.senderIdType ===
        "TRAI_SMS_HEADER"
    ) {

        return "SMS";

    }

    if (
        /\bwhatsapp\b/.test(
            lower
        ) ||
        lower.includes(
            "end-to-end encrypted"
        )
    ) {

        return "WhatsApp";

    }

    if (
        /\btelegram\b/.test(
            lower
        )
    ) {

        return "Telegram";

    }

    if (
        /\binstagram\b/.test(
            lower
        )
    ) {

        return "Instagram DM";

    }

    if (
        /\bmessenger\b/.test(
            lower
        )
    ) {

        return "Messenger";

    }

    if (
        /\bgmail\b/.test(
            lower
        ) ||
        /\boutlook\b/.test(
            lower
        ) ||
        /\byahoo mail\b/.test(
            lower
        ) ||
        /\bsubject\s*:/i.test(
            text
        )
    ) {

        return "Email";

    }

    if (
        /\bsms\b/.test(
            lower
        ) ||
        /\botp\b/.test(
            lower
        ) ||
        /\bsender\b/.test(
            lower
        )
    ) {

        return "SMS";

    }

    return "Website / Chat";

}

/* =========================================================
   MESSAGE CONTENT CLEANING
========================================================= */

function extractMessageText(
    text,
    senderInfo
) {

    let lines =
        text
            .split("\n")
            .map(
                line =>
                    line.trim()
            )
            .filter(Boolean);

    const output = [];

    for (
        const line
        of lines
    ) {

        if (
            /^\d{1,2}:\d{2}/
                .test(line)
        ) {
            continue;
        }

        if (
            /^(today|yesterday)$/i
                .test(line)
        ) {
            continue;
        }

        if (
            /^[\d\s:%@|•]+$/
                .test(line)
        ) {
            continue;
        }

        if (
            /^[A-Z]{2}-[A-Z0-9]{2,11}(?:-[PST])?$/i
                .test(line)
        ) {
            continue;
        }

        if (
            senderInfo.senderId &&
            line
                .toUpperCase()
                .trim() ===
                senderInfo.senderId
        ) {
            continue;
        }

        output.push(
            line
        );

    }

    return output
        .join("\n")
        .trim();

}

/* =========================================================
   DATE / TIME
========================================================= */

function extractDate(
    text
) {

    const match =
        text.match(
            /\b(?:today|yesterday|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b/i
        );

    return match
        ? match[0]
        : "";

}

function extractTime(
    text
) {

    const match =
        text.match(
            /\b\d{1,2}:\d{2}\s*(?:AM|PM)?\b/i
        );

    return match
        ? match[0]
        : "";

}

/* =========================================================
   COMPLETE MESSAGE ANALYSIS
========================================================= */

async function analyzeMessageText(
    extractedText
) {

    const text =
        cleanText(
            extractedText
        );

    const senderInfo =
        extractSenderInfo(
            text
        );

    const senderVerification =
        await verifyTRAIHeader(
            senderInfo
        );

    const urls =
        extractMessageUrls(
            text
        );

    const domains =
        extractDomains(
            urls
        );

    const organizations =
        extractOrganizations(
            text
        );

    const platform =
        detectPlatform(
            text,
            senderInfo
        );

    const phoneNumbers =
        extractMessagePhones(
            text
        );

    const emailAddresses =
        extractMessageEmails(
            text
        );

    const sensitiveRequests =
        detectSensitiveRequests(
            text
        );

    const suspiciousIndicators =
        detectSuspiciousIndicators(
            text,
            urls
        );

    const messageText =
        extractMessageText(
            text,
            senderInfo
        );

    return {

        platform,

        senderId:
            senderInfo.senderId,

        senderIds:
            senderInfo.senderIds,

        routingPrefix:
            senderInfo.routingPrefix,

        baseHeader:
            senderInfo.baseHeader,

        senderCategory:
            senderInfo.category,

        senderIdType:
            senderInfo.senderIdType,

        senderIdConfidence:
            senderInfo.senderIdConfidence,

        senderVerification,

        senderName:
            senderVerification.principalEntityName ||
            (
                organizations.length
                    ? organizations[0]
                    : ""
            ),

        phoneNumbers,

        emailAddresses,

        messageText,

        urls,

        domains,

        organizations,

        brands:
            organizations,

        sensitiveRequests,

        suspiciousIndicators,

        visibleDate:
            extractDate(
                text
            ),

        visibleTime:
            extractTime(
                text
            ),

        extractionConfidence:
            text.length > 50
                ? "High"
                : text.length > 10
                    ? "Medium"
                    : "Low",

        analysis: {

            aiEnabled:
                false,

            engine:
                "rule-based",

            cost:
                "FREE"

        },

        reason:
            "Screenshot analyzed using free local OCR and official TRAI sender-header verification."

    };

}

/* =========================================================
   MESSAGE HEALTH
========================================================= */

app.get(
    "/api/message-health",
    async (req, res) => {

        if (
            mongoReady &&
            traiCollection
        ) {

            try {

                traiDocuments =
                    await traiCollection.countDocuments();

            } catch {

                traiDocuments =
                    0;

            }

        }

        res.json({

            ok:
                true,

            service:
                "SAFNEX NOVA Unified Message Analyzer",

            version:
                "8.0",

            aiConfigured:
                false,

            aiModel:
                null,

            ocrConfigured:
                ocrReady,

            ocrEngine:
                "Tesseract.js",

            mongoConfigured:
                Boolean(
                    MONGODB_URI
                ),

            mongoConnected:
                mongoReady,

            traiCollection:
                MONGODB_COLLECTION,

            traiDocuments,

            cost:
                "FREE"

        });

    }
);

/* =========================================================
   MESSAGE ANALYZER
========================================================= */

app.post(
    "/api/message-analyze",
    upload.single("screenshot"),
    async (req, res) => {
        try {

            if (
                !ocrReady ||
                !ocrWorker
            ) {

                return res.status(
                    503
                ).json({

                    ok:
                        false,

                    error:
                        "OCR_NOT_READY",

                    message:
                        "Free OCR engine is still starting. Please try again shortly."

                });

            }

            /*
              Accept all of these:

              {
                screenshot: "data:image/jpeg;base64,..."
              }

              OR

              {
                image: "data:image/png;base64,..."
              }

              OR

              {
                imageBase64: "..."
              }
            */

          let imageBuffer = req.file?.buffer || null;

if (!imageBuffer) {
    const screenshot =
        req.body?.screenshot ||
        req.body?.image ||
        req.body?.imageBase64;

    if (screenshot) {
        imageBuffer =
            extractBase64Image(
                screenshot
            );
    }
}

if (!imageBuffer) {
    return res.status(
        400
    ).json({
        ok: false,
        error: "NO_SCREENSHOT",
        message: "Screenshot image is required."
    });
}
            if (!imageBuffer) {

                return res.status(
                    400
                ).json({

                    ok:
                        false,

                    error:
                        "INVALID_IMAGE",

                    message:
                        "Invalid Base64 screenshot image."

                });

            }

            if (
                imageBuffer.length >
                8 * 1024 * 1024
            ) {

                return res.status(
                    413
                ).json({

                    ok:
                        false,

                    error:
                        "IMAGE_TOO_LARGE",

                    message:
                        "Screenshot must be smaller than 8 MB."

                });

            }

            console.log("");
            console.log(
                "=============================================="
            );
            console.log(
                "SAFNEX NOVA MESSAGE ANALYZER"
            );
            console.log(
                "=============================================="
            );

            console.log(
                `Image size: ${(imageBuffer.length / 1024).toFixed(1)} KB`
            );

            console.log(
                "Running Tesseract OCR..."
            );

            const {
                data
            } =
                await ocrWorker.recognize(
                    imageBuffer
                );

            const extractedText =
                cleanText(
                    data?.text || ""
                );

            console.log(
                "OCR completed."
            );

            console.log(
                "OCR TEXT:"
            );

            console.log(
                extractedText
            );

            if (!extractedText) {

                return res.json({

                    ok:
                        true,

                    result: {

                        platform:
                            "Unknown",

                        senderId:
                            "",

                        senderIds:
                            [],

                        routingPrefix:
                            "",

                        baseHeader:
                            "",

                        senderCategory:
                            "",

                        senderIdType:
                            "NOT_FOUND",

                        senderIdConfidence:
                            "Low",

                        senderVerification: {

                            status:
                                "SENDER_ID_NOT_FOUND",

                            verified:
                                false,

                            found:
                                false,

                            source:
                                "TRAI_OFFICIAL_DATASET",

                            principalEntityName:
                                "",

                            matchedHeader:
                                "",

                            message:
                                "No readable sender ID was extracted."

                        },

                        senderName:
                            "",

                        phoneNumbers:
                            [],

                        emailAddresses:
                            [],

                        messageText:
                            "",

                        urls:
                            [],

                        domains:
                            [],

                        organizations:
                            [],

                        brands:
                            [],

                        sensitiveRequests:
                            [],

                        suspiciousIndicators:
                            [],

                        visibleDate:
                            "",

                        visibleTime:
                            "",

                        extractionConfidence:
                            "Low",

                        analysis: {

                            aiEnabled:
                                false,

                            engine:
                                "rule-based",

                            cost:
                                "FREE"

                        },

                        reason:
                            "No readable text was detected."

                    },

                    ocr: {

                        engine:
                            "Tesseract.js",

                        text:
                            "",

                        confidence:
                            data?.confidence ??
                            null

                    }

                });

            }

            const result =
                await analyzeMessageText(
                    extractedText
                );

            console.log(
                `Platform    : ${result.platform}`
            );

            console.log(
                `Sender ID   : ${result.senderId || "Not found"}`
            );

            console.log(
                `Base Header : ${result.baseHeader || "Not found"}`
            );

            console.log(
                `TRAI Status : ${result.senderVerification.status}`
            );

            console.log(
                `TRAI Entity : ${result.senderVerification.principalEntityName || "Not found"}`
            );

            console.log(
                "=============================================="
            );

            return res.json({

                ok:
                    true,

                result,

                /*
                  Also expose important values at top level
                  so frontend implementations using either
                  structure can work.
                */

                platform:
                    result.platform,

                senderId:
                    result.senderId,

                baseHeader:
                    result.baseHeader,

                senderVerification:
                    result.senderVerification,

                messageText:
                    result.messageText,

                urls:
                    result.urls,

                domains:
                    result.domains,

                phoneNumbers:
                    result.phoneNumbers,

                emailAddresses:
                    result.emailAddresses,

                organizations:
                    result.organizations,

                sensitiveRequests:
                    result.sensitiveRequests,

                suspiciousIndicators:
                    result.suspiciousIndicators,

                ocr: {

                    engine:
                        "Tesseract.js",

                    text:
                        extractedText,

                    confidence:
                        data?.confidence ??
                        null

                }

            });

        } catch (error) {

            console.error(
                "MESSAGE ANALYZER ERROR:"
            );

            console.error(
                error
            );

            return res.status(
                500
            ).json({

                ok:
                    false,

                error:
                    "MESSAGE_ANALYZER_ERROR",

                message:
                    "Unable to process the screenshot.",

                details:
                    process.env.NODE_ENV ===
                    "development"
                        ? error.message
                        : undefined

            });

        }

    }
);

/* =========================================================
   UNIFIED HEALTH
========================================================= */

app.get(
    "/api/health",
    async (req, res) => {

        if (
            mongoReady &&
            traiCollection
        ) {

            try {

                traiDocuments =
                    await traiCollection.countDocuments();

            } catch {

                traiDocuments =
                    0;

            }

        }

        res.json({

            ok:
                true,

            service:
                "SAFNEX NOVA Unified Analyzer",

            version:
                "8.0",

            analyzerEngine:
                "rule-based",

            aiConfigured:
                false,

            cost:
                "FREE",

            linkAnalyzer:
                "POST /api/analyze",

            phoneAnalyzer:
                "POST /api/phone-check",

            phoneValidation:
                "POST /api/phone-validate",

            messageAnalyzer:
                "POST /api/message-analyze",

            messageHealth:
                "GET /api/message-health",

            ocrConfigured:
                ocrReady,

            ocrEngine:
                "Tesseract.js",

            mongoConnected:
                mongoReady,

            traiCollection:
                MONGODB_COLLECTION,

            traiDocuments

        });

    }
);

/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            ok:
                true,

            service:
                "SAFNEX NOVA Unified Analyzer",

            features: [

                "LINK",
                "PHONE",
                "MESSAGE"

            ],

            endpoints: {

                link:
                    "POST /api/analyze",

                phone:
                    "POST /api/phone-check",

                phoneValidation:
                    "POST /api/phone-validate",

                message:
                    "POST /api/message-analyze",

                health:
                    "GET /api/health"

            },

            engine:
                "Rule-based + Tesseract.js + MongoDB TRAI",

            cost:
                "FREE"

        });

    }
);

/* =========================================================
   API 404
========================================================= */

app.use(
    "/api",
    (req, res) => {

        res.status(
            404
        ).json({

            ok:
                false,

            error:
                "API endpoint not found.",

            path:
                req.path

        });

    }
);

/* =========================================================
   GENERAL ERROR
========================================================= */

app.use(
    (
        error,
        req,
        res,
        next
    ) => {

        console.error(
            "SERVER ERROR:",
            error
        );

        if (
            res.headersSent
        ) {

            return next(
                error
            );

        }

        res.status(
            500
        ).json({

            ok:
                false,

            error:
                "Internal server error."

        });

    }
);

/* =========================================================
   OCR INITIALIZATION
========================================================= */

async function initializeOCR() {

    try {

        console.log(
            "Initializing Tesseract.js..."
        );

        ocrWorker =
            await createWorker(
                OCR_LANGUAGE
            );

        ocrReady =
            true;

        console.log(
            "✅ Tesseract OCR ready"
        );

    } catch (error) {

        ocrReady =
            false;

        console.error(
            "❌ OCR initialization failed:"
        );

        console.error(
            error.message
        );

    }

}

/* =========================================================
   MONGODB INITIALIZATION
========================================================= */

async function initializeMongoDB() {

    if (!MONGODB_URI) {

        console.log(
            "⚠️ MONGODB_URI is not configured."
        );

        console.log(
            "TRAI verification will remain NOT_VERIFIED."
        );

        return;

    }

    try {

        console.log("");
        console.log(
            "Connecting to MongoDB Atlas..."
        );

        mongoClient =
            new MongoClient(
                MONGODB_URI,
                {
                    serverSelectionTimeoutMS:
                        10000
                }
            );

        await mongoClient.connect();

        mongoDatabase =
            mongoClient.db(
                MONGODB_DATABASE
            );

        traiCollection =
            mongoDatabase.collection(
                MONGODB_COLLECTION
            );

        traiDocuments =
            await traiCollection.countDocuments();

        try {

            await traiCollection.createIndex(
                {
                    Header:
                        1
                }
            );

        } catch {

            // index already exists

        }

        mongoReady =
            true;

        console.log(
            "✅ MongoDB connected"
        );

        console.log(
            `Database   : ${MONGODB_DATABASE}`
        );

        console.log(
            `Collection : ${MONGODB_COLLECTION}`
        );

        console.log(
            `Documents  : ${traiDocuments}`
        );

    } catch (error) {

        mongoReady =
            false;

        traiCollection =
            null;

        console.error(
            "❌ MongoDB connection failed:"
        );

        console.error(
            error.message
        );

    }

}

/* =========================================================
   START
========================================================= */

async function startServer() {

    await initializeOCR();

    await initializeMongoDB();

    app.listen(
        PORT,
        () => {

            console.log("");
            console.log(
                "================================================"
            );

            console.log(
                "       SAFNEX NOVA UNIFIED ANALYZER"
            );

            console.log(
                "================================================"
            );

            console.log(
                `Server       : http://localhost:${PORT}`
            );

            console.log(
                `Health       : http://localhost:${PORT}/api/health`
            );

            console.log(
                `LINK         : POST /api/analyze`
            );

            console.log(
                `PHONE        : POST /api/phone-check`
            );

            console.log(
                `PHONE VALID  : POST /api/phone-validate`
            );

            console.log(
                `MESSAGE      : POST /api/message-analyze`
            );

            console.log(
                `MESSAGE HEALTH: GET /api/message-health`
            );

            console.log(
                `OCR          : ${ocrReady ? "READY" : "STARTING"}`
            );

            console.log(
                `MongoDB      : ${mongoReady ? "CONNECTED" : "NOT CONNECTED"}`
            );

            console.log(
                `TRAI Records : ${traiDocuments}`
            );

            console.log(
                "AI           : NONE"
            );

            console.log(
                "Cost         : FREE"
            );

            console.log(
                "================================================"
            );

        }
    );

}

startServer();

