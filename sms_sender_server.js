import dns from "node:dns";

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import OpenAI from "openai";
import { MongoClient } from "mongodb";

// =========================================================
// DNS
// =========================================================

dns.setServers(["8.8.8.8", "1.1.1.1"]);

dotenv.config();

// =========================================================
// EXPRESS
// =========================================================

const app = express();

const PORT = Number(
    process.env.SMS_PORT || 4001
);

const MONGODB_URI =
    process.env.MONGODB_URI;

const DB_NAME =
    process.env.DB_NAME ||
    "safnex_nova";

const COLLECTION_NAME =
    process.env.MONGODB_COLLECTION ||
    "trai_sms_headers";

const OPENAI_API_KEY =
    process.env.OPENAI_API_KEY;

const OPENAI_MODEL =
    process.env.OPENAI_MODEL ||
    "gpt-5.6-luna";

// =========================================================
// ENV CHECK
// =========================================================

if (!MONGODB_URI) {
    console.error(
        "❌ MONGODB_URI is missing in .env"
    );
    process.exit(1);
}

if (!OPENAI_API_KEY) {
    console.error(
        "❌ OPENAI_API_KEY is missing in .env"
    );
    process.exit(1);
}

// =========================================================
// OPENAI
// =========================================================

const openai = new OpenAI({
    apiKey: OPENAI_API_KEY
});

// =========================================================
// MONGODB
// =========================================================

let mongoClient = null;
let db = null;
let headersCollection = null;

// =========================================================
// EXPRESS CONFIG
// =========================================================

app.use(
    cors({
        origin: true,
        methods: [
            "GET",
            "POST",
            "OPTIONS"
        ],
        allowedHeaders: [
            "Content-Type"
        ]
    })
);

app.use(
    express.json({
        limit: "15mb"
    })
);

// =========================================================
// HELPERS
// =========================================================

function cleanString(value) {
    if (typeof value !== "string") {
        return "";
    }

    return value.trim();
}


// ---------------------------------------------------------
// Normalize simple header text
// ---------------------------------------------------------

function normalizeHeader(value) {
    return cleanString(value)
        .toUpperCase()
        .replace(/\s+/g, "");
}


// ---------------------------------------------------------
// Remove data URL prefix
// ---------------------------------------------------------

function removeDataUrlPrefix(base64) {

    if (!base64) {
        return "";
    }

    return base64.replace(
        /^data:image\/[a-zA-Z0-9.+-]+;base64,/i,
        ""
    );
}


// ---------------------------------------------------------
// Detect image MIME type
// ---------------------------------------------------------

function getImageMimeType(base64) {

    if (
        typeof base64 === "string" &&
        base64.startsWith("data:image/")
    ) {

        const match =
            base64.match(
                /^data:(image\/[a-zA-Z0-9.+-]+);base64,/i
            );

        if (match?.[1]) {
            return match[1];
        }
    }

    return "image/jpeg";
}


// ---------------------------------------------------------
// Escape regex characters
// ---------------------------------------------------------

function escapeRegex(value) {

    return value.replace(
        /[.*+?^${}()|[\]\\]/g,
        "\\$&"
    );
}

// =========================================================
// SMS SENDER FORMAT PARSER
// =========================================================
//
// Example:
//
// JD-TNCRDT-P
//
// JD      = telecom / routing prefix
// TNCRDT  = header candidate
// P       = promotional category
//
// Other examples:
//
// AD-XXXXXX
// VM-XXXXXX
// JD-XXXXXX
// XX-XXXXXX
//
// IMPORTANT:
// This parser does NOT decide whether a sender is genuine.
// It only separates the visible sender format.
//

function parseSMSHeader(senderId) {

    const original =
        cleanString(senderId);

    if (!original) {

        return {
            originalSenderId: "",
            prefix: "",
            baseHeader: "",
            category: "",
            normalizedHeader: ""
        };
    }

    const value =
        original
            .toUpperCase()
            .replace(/\s+/g, "");

    // -----------------------------------------------------
    // Modern Indian SMS sender format
    //
    // XX-XXXXXX
    // XX-XXXXXX-P
    // XX-XXXXXX-S
    // XX-XXXXXX-T
    //
    // P = Promotional
    // S = Service
    // T = Transactional
    // G = Government / other supported suffix
    // -----------------------------------------------------

    const match =
        value.match(
            /^([A-Z0-9]{2})-([A-Z0-9]{1,11})(?:-([PSTG]))?$/
        );

    if (match) {

        return {

            originalSenderId:
                original,

            prefix:
                match[1],

            baseHeader:
                match[2],

            category:
                match[3] || "",

            normalizedHeader:
                normalizeHeader(
                    match[2]
                )
        };
    }

    // -----------------------------------------------------
    // Fallback
    //
    // If sender is already a simple header:
    //
    // KOTAKB
    // BOBCRD
    // APCRDA
    //
    // Treat the whole value as the header candidate.
    // -----------------------------------------------------

    return {

        originalSenderId:
            original,

        prefix:
            "",

        baseHeader:
            value,

        category:
            "",

        normalizedHeader:
            value
    };
}

// =========================================================
// CATEGORY DESCRIPTION
// =========================================================

function getCategoryDescription(category) {

    switch (category) {

        case "P":
            return "Promotional";

        case "S":
            return "Service";

        case "T":
            return "Transactional";

        case "G":
            return "Government / Other";

        default:
            return "Not specified";
    }
}

// =========================================================
// MONGODB CONNECTION
// =========================================================

async function createMongoClient() {

    console.log(
        "Connecting to MongoDB Atlas..."
    );

    // -----------------------------------------------------
    // SRV URI
    // -----------------------------------------------------

    if (
        MONGODB_URI.startsWith(
            "mongodb+srv://"
        )
    ) {

        console.log(
            "MongoDB SRV detected. Resolving Atlas hosts..."
        );

        const url =
            new URL(MONGODB_URI);

        const srvHost =
            url.hostname;

        const srvRecords =
            await dns.promises.resolveSrv(
                `_mongodb._tcp.${srvHost}`
            );

        if (!srvRecords.length) {

            throw new Error(
                "MongoDB Atlas SRV returned no hosts"
            );
        }

        console.log(
            "Atlas hosts:"
        );

        for (
            const record of srvRecords
        ) {

            console.log(
                `   ${record.name}:${record.port}`
            );
        }

        // -------------------------------------------------
        // Encode credentials
        // -------------------------------------------------

        const username =
            encodeURIComponent(
                decodeURIComponent(
                    url.username
                )
            );

        const password =
            encodeURIComponent(
                decodeURIComponent(
                    url.password
                )
            );

        // -------------------------------------------------
        // Build normal mongodb:// URI
        // -------------------------------------------------

        const hosts =
            srvRecords
                .map(
                    (record) =>
                        `${record.name}:${record.port}`
                )
                .join(",");

        const standardUri =
            `mongodb://${username}:${password}@${hosts}/` +
            `?tls=true` +
            `&authSource=admin` +
            `&retryWrites=true` +
            `&w=majority` +
            `&appName=Cluster0`;

        return new MongoClient(
            standardUri,
            {
                serverSelectionTimeoutMS: 15000,
                connectTimeoutMS: 15000
            }
        );
    }

    // -----------------------------------------------------
    // Normal mongodb:// URI
    // -----------------------------------------------------

    return new MongoClient(
        MONGODB_URI,
        {
            serverSelectionTimeoutMS: 15000,
            connectTimeoutMS: 15000
        }
    );
}


// =========================================================
// CONNECT MONGODB
// =========================================================

async function connectMongoDB() {

    mongoClient =
        await createMongoClient();

    await mongoClient.connect();

    db =
        mongoClient.db(
            DB_NAME
        );

    headersCollection =
        db.collection(
            COLLECTION_NAME
        );

    // -----------------------------------------------------
    // Ping
    // -----------------------------------------------------

    await db.command({
        ping: 1
    });

    console.log(
        "✅ MongoDB connected"
    );

    console.log(
        `   Database   : ${DB_NAME}`
    );

    console.log(
        `   Collection : ${COLLECTION_NAME}`
    );

    const count =
        await headersCollection.countDocuments();

    console.log(
        `   Documents  : ${count.toLocaleString()}`
    );

    // -----------------------------------------------------
    // Header index
    // -----------------------------------------------------

    try {

        await headersCollection.createIndex(
            {
                Header: 1
            },
            {
                name:
                    "header_exact_lookup"
            }
        );

        console.log(
            "✅ Header index ready"
        );

    } catch (error) {

        console.warn(
            "⚠️ Could not create Header index:",
            error.message
        );
    }
}

// =========================================================
// TRAI HEADER LOOKUP
// =========================================================

async function findRegisteredHeader(
    senderId
) {

    const parsed =
        parseSMSHeader(
            senderId
        );

    if (
        !parsed.normalizedHeader
    ) {

        return {

            found: false,

            reason:
                "EMPTY_HEADER",

            parsed,

            record: null
        };
    }

    const header =
        parsed.normalizedHeader;

    // -----------------------------------------------------
    // Exact database match
    // -----------------------------------------------------

    const exactRegex =
        new RegExp(
            `^${escapeRegex(header)}$`,
            "i"
        );

    const record =
        await headersCollection.findOne({
            Header: exactRegex
        });

    if (record) {

        return {

            found: true,

            reason:
                "EXACT_MATCH",

            parsed,

            record
        };
    }

    // -----------------------------------------------------
    // Not found
    //
    // IMPORTANT:
    // This does NOT mean the SMS is fake.
    //
    // It only means the candidate header was not found
    // inside the imported TRAI dataset.
    // -----------------------------------------------------

    return {

        found: false,

        reason:
            "NOT_FOUND_IN_IMPORTED_DATASET",

        parsed,

        record: null
    };
}

// =========================================================
// AI SMS SENDER EXTRACTION
// =========================================================

async function detectSenderIdFromScreenshot(
    screenshotBase64
) {

    const cleanBase64 =
        removeDataUrlPrefix(
            screenshotBase64
        );

    if (!cleanBase64) {

        throw new Error(
            "Screenshot data is empty"
        );
    }

    const mimeType =
        getImageMimeType(
            screenshotBase64
        );

    const imageDataUrl =
        `data:${mimeType};base64,${cleanBase64}`;

    const response =
        await openai.responses.create({

            model:
                OPENAI_MODEL,

            input: [

                {

                    role: "user",

                    content: [

                        {
                            type:
                                "input_text",

                            text: `

You are the SMS Sender ID extraction component of SAFNEX NOVA.

Your ONLY job is to inspect the screenshot and determine whether it is an SMS screenshot and, if it is, extract the EXACT visible SMS Sender ID.

IMPORTANT RULES:

1. Do NOT verify whether the sender is genuine.

2. Do NOT decide whether the SMS is a scam.

3. Do NOT invent a sender ID.

4. Do NOT correct spelling.

5. Do NOT guess missing characters.

6. Preserve the sender ID exactly as visible.

7. Preserve hyphens.

8. Preserve letters and numbers.

9. Do not use the message body as the sender ID.

10. Do not use a phone number as the sender ID.

11. Do not use a company name as the sender ID unless that exact text is visibly shown as the SMS sender.

12. If the sender ID is not clearly visible, return an empty senderId.

13. Determine whether the screenshot appears to be an SMS interface.

14. Return JSON only.

Typical Indian SMS sender formats can look like:

AD-XXXXXX
VM-XXXXXX
JD-XXXXXX
DM-XXXXXX
XX-XXXXXX

These are ONLY examples.

Do not assume every screenshot follows these formats.

Return exactly:

{
  "isSMS": true,
  "senderId": "EXACT_VISIBLE_SENDER_ID",
  "confidence": "High",
  "reason": "Sender ID clearly visible"
}

If it is not an SMS screenshot:

{
  "isSMS": false,
  "senderId": "",
  "confidence": "High",
  "reason": "Screenshot does not appear to be an SMS"
}

If it looks like SMS but the sender ID cannot be read:

{
  "isSMS": true,
  "senderId": "",
  "confidence": "Low",
  "reason": "SMS interface detected but sender ID is not clearly visible"
}

`
                        },

                        {
                            type:
                                "input_image",

                            image_url:
                                imageDataUrl
                        }

                    ]
                }

            ]
        });

    const text =
        response.output_text?.trim() ||
        "";

    if (!text) {

        throw new Error(
            "OpenAI returned an empty response"
        );
    }

    let parsed;

    try {

        parsed =
            JSON.parse(text);

    } catch {

        const cleaned =
            text
                .replace(
                    /^```json/i,
                    ""
                )
                .replace(
                    /^```/i,
                    ""
                )
                .replace(
                    /```$/i,
                    ""
                )
                .trim();

        try {

            parsed =
                JSON.parse(
                    cleaned
                );

        } catch {

            throw new Error(
                "Could not parse AI sender ID response"
            );
        }
    }

    return {

        isSMS:
            Boolean(
                parsed.isSMS
            ),

        senderId:
            cleanString(
                parsed.senderId
            ),

        confidence:
            cleanString(
                parsed.confidence
            ) || "Low",

        reason:
            cleanString(
                parsed.reason
            ) ||
            "Unable to determine sender ID"
    };
}

// =========================================================
// HEALTH
// =========================================================

app.get(
    "/api/sms-sender-health",
    async (req, res) => {

        try {

            const connected =
                Boolean(
                    headersCollection
                );

            let documents =
                null;

            if (connected) {

                documents =
                    await headersCollection.countDocuments();
            }

            res.json({

                ok: true,

                service:
                    "SAFNEX NOVA SMS Sender ID Detector",

                version:
                    "4.0",

                aiConfigured:
                    Boolean(
                        OPENAI_API_KEY
                    ),

                aiModel:
                    OPENAI_MODEL,

                mongodbConnected:
                    connected,

                database:
                    DB_NAME,

                collection:
                    COLLECTION_NAME,

                headerDocuments:
                    documents

            });

        } catch (error) {

            res.status(500).json({

                ok: false,

                error:
                    error.message

            });
        }
    }
);

// =========================================================
// VERIFY ALREADY KNOWN SENDER ID
// =========================================================

app.post(
    "/api/verify-sms-sender",
    async (req, res) => {

        try {

            const senderId =
                cleanString(
                    req.body?.senderId
                );

            if (!senderId) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "senderId is required"

                });
            }

            const lookup =
                await findRegisteredHeader(
                    senderId
                );

            // -------------------------------------------------
            // REGISTERED
            // -------------------------------------------------

            if (lookup.found) {

                const record =
                    lookup.record;

                return res.json({

                    ok: true,

                    senderVerification:
                        "REGISTERED",

                    status:
                        "Registered Sender",

                    senderId,

                    parsedSender: {

                        prefix:
                            lookup.parsed.prefix,

                        headerCandidate:
                            lookup.parsed.baseHeader,

                        category:
                            lookup.parsed.category,

                        categoryDescription:
                            getCategoryDescription(
                                lookup.parsed.category
                            )

                    },

                    registeredHeader:
                        record.Header ?? "",

                    registeredEntity:
                        record[
                            "Principal Entity Name"
                        ] ?? "",

                    matchedRecord:
                        record

                });
            }

            // -------------------------------------------------
            // NOT FOUND IN IMPORTED DATASET
            // -------------------------------------------------

            return res.json({

                ok: true,

                senderVerification:
                    "NOT_FOUND_IN_DATASET",

                status:
                    "Header Not Found In Imported TRAI Dataset",

                senderId,

                parsedSender: {

                    prefix:
                        lookup.parsed.prefix,

                    headerCandidate:
                        lookup.parsed.baseHeader,

                    category:
                        lookup.parsed.category,

                    categoryDescription:
                        getCategoryDescription(
                            lookup.parsed.category
                        )

                },

                registeredHeader:
                    "",

                registeredEntity:
                    "",

                matchedRecord:
                    null,

                message:
                    "The sender header was not found in the imported TRAI dataset. This does not by itself mean the SMS is fraudulent."

            });

        } catch (error) {

            console.error(
                "Sender verification error:",
                error
            );

            res.status(500).json({

                ok: false,

                error:
                    error.message

            });
        }
    }
);

// =========================================================
// SCREENSHOT → AI → TRAI DATABASE
// =========================================================

app.post(
    "/api/detect-sms-sender",
    async (req, res) => {

        try {

            const screenshot =
                req.body?.image ||
                req.body?.screenshot ||
                req.body?.imageBase64;

            if (!screenshot) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "Screenshot base64 data is required"

                });
            }

            console.log(
                "📸 SMS screenshot received"
            );

            // -------------------------------------------------
            // STEP 1: AI detection
            // -------------------------------------------------

            const detection =
                await detectSenderIdFromScreenshot(
                    screenshot
                );

            console.log(
                "AI detection:",
                detection
            );

            // -------------------------------------------------
            // NOT SMS
            // -------------------------------------------------

            if (!detection.isSMS) {

                return res.json({

                    ok: true,

                    result: {

                        isSMS:
                            false,

                        senderId:
                            "",

                        confidence:
                            detection.confidence,

                        reason:
                            detection.reason,

                        senderVerification:
                            "NOT_APPLICABLE",

                        status:
                            "Not an SMS screenshot",

                        registeredEntity:
                            "",

                        registeredHeader:
                            ""

                    }

                });
            }

            // -------------------------------------------------
            // SMS BUT SENDER ID NOT DETECTED
            // -------------------------------------------------

            if (!detection.senderId) {

                return res.json({

                    ok: true,

                    result: {

                        isSMS:
                            true,

                        senderId:
                            "",

                        confidence:
                            detection.confidence,

                        reason:
                            detection.reason,

                        senderVerification:
                            "SENDER_ID_NOT_DETECTED",

                        status:
                            "Sender ID Not Detected",

                        registeredEntity:
                            "",

                        registeredHeader:
                            ""

                    }

                });
            }

            // -------------------------------------------------
            // STEP 2: TRAI DATABASE LOOKUP
            // -------------------------------------------------

            const lookup =
                await findRegisteredHeader(
                    detection.senderId
                );

            // -------------------------------------------------
            // REGISTERED
            // -------------------------------------------------

            if (lookup.found) {

                const record =
                    lookup.record;

                console.log(
                    `🟢 Registered Sender: ${detection.senderId}`
                );

                return res.json({

                    ok: true,

                    result: {

                        isSMS:
                            true,

                        senderId:
                            detection.senderId,

                        confidence:
                            detection.confidence,

                        reason:
                            detection.reason,

                        senderVerification:
                            "REGISTERED",

                        status:
                            "Registered Sender",

                        parsedSender: {

                            prefix:
                                lookup.parsed.prefix,

                            headerCandidate:
                                lookup.parsed.baseHeader,

                            category:
                                lookup.parsed.category,

                            categoryDescription:
                                getCategoryDescription(
                                    lookup.parsed.category
                                )

                        },

                        registeredHeader:
                            record.Header ?? "",

                        registeredEntity:
                            record[
                                "Principal Entity Name"
                            ] ?? "",

                        matchedRecord:
                            record,

                        database:
                            DB_NAME,

                        collection:
                            COLLECTION_NAME

                    }

                });
            }

            // -------------------------------------------------
            // NOT FOUND IN IMPORTED DATASET
            // -------------------------------------------------

            console.log(
                `🟡 Header not found in imported dataset: ${detection.senderId}`
            );

            return res.json({

                ok: true,

                result: {

                    isSMS:
                        true,

                    senderId:
                        detection.senderId,

                    confidence:
                        detection.confidence,

                    reason:
                        detection.reason,

                    senderVerification:
                        "NOT_FOUND_IN_DATASET",

                    status:
                        "Header Not Found In Imported TRAI Dataset",

                    parsedSender: {

                        prefix:
                            lookup.parsed.prefix,

                        headerCandidate:
                            lookup.parsed.baseHeader,

                        category:
                            lookup.parsed.category,

                        categoryDescription:
                            getCategoryDescription(
                                lookup.parsed.category
                            )

                    },

                    registeredHeader:
                        "",

                    registeredEntity:
                        "",

                    matchedRecord:
                        null,

                    database:
                        DB_NAME,

                    collection:
                        COLLECTION_NAME,

                    message:
                        "The sender header was not found in the imported TRAI dataset. This does not by itself mean the SMS is fraudulent."

                }

            });

        } catch (error) {

            console.error(
                "❌ SMS sender detection error:",
                error
            );

            res.status(500).json({

                ok: false,

                error:
                    error.message

            });
        }
    }
);

// =========================================================
// API 404
// =========================================================

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            ok: false,

            error:
                "API endpoint not found",

            path:
                req.originalUrl

        });
    }
);

// =========================================================
// GLOBAL ERROR
// =========================================================

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled server error:",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        res.status(500).json({

            ok: false,

            error:
                error.message ||
                "Internal server error"

        });
    }
);

// =========================================================
// START SERVER
// =========================================================

async function startServer() {

    try {

        await connectMongoDB();

        app.listen(
            PORT,
            () => {

                console.log("");

                console.log(
                    "=============================================="
                );

                console.log(
                    "SAFNEX NOVA SMS Sender ID Detector"
                );

                console.log(
                    "=============================================="
                );

                console.log(
                    `Server  : http://localhost:${PORT}`
                );

                console.log(
                    `Health  : http://localhost:${PORT}/api/sms-sender-health`
                );

                console.log(
                    "Detect  : POST /api/detect-sms-sender"
                );

                console.log(
                    "Verify  : POST /api/verify-sms-sender"
                );

                console.log(
                    `MongoDB : ${DB_NAME}.${COLLECTION_NAME}`
                );

                console.log(
                    `AI      : ${OPENAI_MODEL}`
                );

                console.log(
                    "=============================================="
                );

                console.log("");
            }
        );

    } catch (error) {

        console.error("");

        console.error(
            "❌ Failed to start SMS Sender ID Detector"
        );

        console.error(
            error.message
        );

        console.error("");

        process.exit(1);
    }
}

startServer();

// =========================================================
// GRACEFUL SHUTDOWN
// =========================================================

async function shutdown(signal) {

    console.log(
        `\n${signal} received. Closing MongoDB...`
    );

    try {

        if (mongoClient) {

            await mongoClient.close();
        }

        console.log(
            "MongoDB connection closed."
        );

    } catch (error) {

        console.error(
            "MongoDB close error:",
            error.message
        );
    }

    process.exit(0);
}

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);