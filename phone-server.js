import express from "express";
import cors from "cors";
import dotenv from "dotenv";

import {
    parsePhoneNumberFromString,
    validatePhoneNumberLength
} from "libphonenumber-js/max";

dotenv.config();

const app = express();

const PORT = Number(process.env.PHONE_PORT || 4000);

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(cors());

app.use(
    express.json({
        limit: "1mb"
    })
);


/* =========================================================
   BASIC HELPERS
========================================================= */

function cleanPhone(value) {
    if (typeof value !== "string") {
        return "";
    }

    return value.trim();
}


function maskPhone(phone) {
    if (!phone) {
        return "";
    }

    const digits =
        phone.replace(/\D/g, "");

    if (digits.length <= 4) {
        return "*".repeat(digits.length);
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


/* =========================================================
   COUNTRY NAMES
========================================================= */

function getCountryName(countryCode) {

    const countries = {

        IN: "India",
        US: "United States",
        CA: "Canada",
        GB: "United Kingdom",
        AU: "Australia",

        AE: "United Arab Emirates",
        SG: "Singapore",
        MY: "Malaysia",

        DE: "Germany",
        FR: "France",
        IT: "Italy",
        ES: "Spain",
        PT: "Portugal",

        NL: "Netherlands",
        BE: "Belgium",
        CH: "Switzerland",
        AT: "Austria",

        NZ: "New Zealand",
        JP: "Japan",
        CN: "China",
        KR: "South Korea",

        RU: "Russia",
        BR: "Brazil",
        MX: "Mexico",

        ZA: "South Africa",

        SA: "Saudi Arabia",
        QA: "Qatar",
        KW: "Kuwait",
        OM: "Oman",
        BH: "Bahrain",

        LK: "Sri Lanka",
        BD: "Bangladesh",
        NP: "Nepal",
        PK: "Pakistan"

    };

    return (
        countries[countryCode] ||
        countryCode ||
        "Unknown"
    );
}


/* =========================================================
   PHONE TYPE
========================================================= */

function readablePhoneType(type) {

    const types = {

        MOBILE:
            "Mobile",

        FIXED_LINE:
            "Fixed Line",

        FIXED_LINE_OR_MOBILE:
            "Fixed Line or Mobile",

        TOLL_FREE:
            "Toll Free",

        PREMIUM_RATE:
            "Premium Rate",

        SHARED_COST:
            "Shared Cost",

        VOIP:
            "VoIP",

        PERSONAL_NUMBER:
            "Personal Number",

        PAGER:
            "Pager",

        UAN:
            "Universal Access Number",

        VOICEMAIL:
            "Voicemail",

        UNKNOWN:
            "Unknown"

    };

    return (
        types[type] ||
        "Unknown"
    );
}


/* =========================================================
   RISK INDICATORS
========================================================= */

function buildRiskIndicators(
    phoneNumber,
    originalInput
) {

    const indicators = [];

    const digits =
        phoneNumber.number.replace(
            /\D/g,
            ""
        );


    /* ================= VALID ================= */

    if (phoneNumber.isValid()) {

        indicators.push({

            level: "positive",

            title:
                "Valid number format",

            detail:
                "The number matches the numbering rules for its detected country."

        });

    }


    /* ================= POSSIBLE ================= */

    if (phoneNumber.isPossible()) {

        indicators.push({

            level: "positive",

            title:
                "Possible number",

            detail:
                "The number length and structure are possible for its numbering plan."

        });

    }


    /* ================= REPEATED DIGITS ================= */

    if (
        /(\d)\1{5,}/.test(
            digits
        )
    ) {

        indicators.push({

            level: "warning",

            title:
                "Repeated digit pattern",

            detail:
                "The number contains an unusual repeated-digit pattern."

        });

    }


    /* ================= REPEATED SEQUENCE ================= */

    if (
        /^(\d{2,4})\1+$/.test(
            digits
        )
    ) {

        indicators.push({

            level: "warning",

            title:
                "Repeated sequence",

            detail:
                "The number contains a repeated numeric sequence."

        });

    }


    /* ================= NATIONAL FORMAT ================= */

    if (
        !originalInput.startsWith("+")
    ) {

        indicators.push({

            level: "info",

            title:
                "National format detected",

            detail:
                "The number was supplied without an international country code. The default country is being used for parsing."

        });

    }


    return indicators;
}


/* =========================================================
   SCORE
========================================================= */

function calculateScore(
    phoneNumber,
    indicators
) {

    let score = 50;


    if (
        phoneNumber.isValid()
    ) {

        score += 35;

    }

    else if (
        phoneNumber.isPossible()
    ) {

        score += 15;

    }

    else {

        score -= 30;

    }


    const warnings =
        indicators.filter(
            item =>
                item.level === "warning"
        ).length;


    score -=
        warnings * 8;


    score =
        Math.max(
            0,
            Math.min(
                100,
                score
            )
        );


    return score;
}


/* =========================================================
   VERDICT
========================================================= */

function getVerdict(
    score,
    valid,
    possible
) {

    if (
        valid &&
        score >= 80
    ) {

        return "Likely Valid";

    }


    if (
        possible &&
        score >= 60
    ) {

        return "Needs Review";

    }


    if (possible) {

        return "Suspicious Format";

    }


    return "Invalid Number";
}


/* =========================================================
   RISK LEVEL
========================================================= */

function getRiskLevel(
    score,
    valid
) {

    if (
        valid &&
        score >= 80
    ) {

        return "LOW RISK";

    }


    if (score >= 60) {

        return "MEDIUM";

    }


    if (score >= 40) {

        return "ELEVATED";

    }


    return "HIGH RISK";
}


/* =========================================================
   PHONE ANALYSIS
========================================================= */

function analyzePhone(
    input,
    defaultCountry = "IN"
) {

    const originalInput =
        cleanPhone(input);


    if (!originalInput) {

        throw new Error(
            "Phone number is required."
        );

    }


    if (
        originalInput.length > 100
    ) {

        throw new Error(
            "Phone number input is too long."
        );

    }


    let phoneNumber;


    try {

        phoneNumber =
            parsePhoneNumberFromString(
                originalInput,
                defaultCountry
            );

    }

    catch {

        throw new Error(
            "Unable to parse the phone number."
        );

    }


    /* =====================================================
       NUMBER COULD NOT BE PARSED
    ===================================================== */

    if (!phoneNumber) {

        return {

            ok: true,

            detected: false,

            input:
                maskPhone(
                    originalInput
                ),

            message:
                "No valid phone-number structure could be detected.",

            securityScore: 0,

            verdict:
                "Invalid Number",

            riskLevel:
                "HIGH RISK",

            confidence:
                "High",

            indicators: [

                {

                    level:
                        "danger",

                    title:
                        "Number could not be parsed",

                    detail:
                        "Check the country code and phone-number format."

                }

            ],

            limitations: [

                "This result is based on phone-number structure only.",

                "It does not identify the private owner of the number.",

                "It does not prove that the number is safe or trustworthy."

            ]

        };

    }


    /* =====================================================
       VALID / POSSIBLE
    ===================================================== */

    const valid =
        phoneNumber.isValid();


    const possible =
        phoneNumber.isPossible();


    /* =====================================================
       TYPE
    ===================================================== */

    let type = "UNKNOWN";


    try {

        type =
            phoneNumber.getType() ||
            "UNKNOWN";

    }

    catch {

        type =
            "UNKNOWN";

    }


    /* =====================================================
       INDICATORS
    ===================================================== */

    const indicators =
        buildRiskIndicators(
            phoneNumber,
            originalInput
        );


    /* =====================================================
       SCORE
    ===================================================== */

    const securityScore =
        calculateScore(
            phoneNumber,
            indicators
        );


    /* =====================================================
       VERDICT
    ===================================================== */

    const verdict =
        getVerdict(
            securityScore,
            valid,
            possible
        );


    /* =====================================================
       RISK
    ===================================================== */

    const riskLevel =
        getRiskLevel(
            securityScore,
            valid
        );


    /* =====================================================
       CONFIDENCE
    ===================================================== */

    let confidence =
        "Low";


    if (valid) {

        confidence =
            "High";

    }

    else if (possible) {

        confidence =
            "Medium";

    }


    /* =====================================================
       RESPONSE
    ===================================================== */

    return {

        ok: true,

        detected: true,

        input:
            maskPhone(
                originalInput
            ),

        securityScore,

        verdict,

        riskLevel,

        confidence,


        phone: {

            countryCode:
                phoneNumber.country,

            country:
                getCountryName(
                    phoneNumber.country
                ),

            callingCode:
                `+${phoneNumber.countryCallingCode}`,

            nationalNumber:
                phoneNumber.nationalNumber,

            internationalFormat:
                phoneNumber.formatInternational(),

            nationalFormat:
                phoneNumber.formatNational(),

            e164:
                phoneNumber.number,

            type:
                readablePhoneType(
                    type
                ),

            valid,

            possible

        },


        indicators,


        limitations: [

            "This analysis validates the number structure and numbering plan.",

            "It does not identify the private owner of the number.",

            "It does not prove that the number is safe or trustworthy.",

            "Carrier or scam-reputation information requires a separate lookup provider."

        ]

    };

}


/* =========================================================
   ROOT
========================================================= */

app.get(
    "/",
    (req, res) => {

        res.json({

            ok: true,

            service:
                "SAFNEX NOVA Phone Detection Server",

            status:
                "online",

            port:
                PORT

        });

    }
);


/* =========================================================
   HEALTH
========================================================= */

app.get(
    "/api/health",
    (req, res) => {

        res.json({

            ok: true,

            service:
                "SAFNEX NOVA Phone Detection Server",

            version:
                "1.0",

            port:
                PORT,

            status:
                "online"

        });

    }
);


/* =========================================================
   PHONE CHECK
========================================================= */

app.post(
    "/api/phone-check",
    (req, res) => {

        try {

            const body =
                req.body || {};


            /*
               Accept all three names so the frontend
               can send phone / phoneNumber / number.
            */

            const phone =
                body.phone ||
                body.phoneNumber ||
                body.number;


            const country =
                body.country ||
                "IN";


            if (!phone) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "Phone number is required."

                });

            }


            const defaultCountry =
                typeof country === "string" &&
                /^[A-Z]{2}$/i.test(
                    country
                )
                    ? country.toUpperCase()
                    : "IN";


            const result =
                analyzePhone(
                    phone,
                    defaultCountry
                );


            return res.json(
                result
            );

        }

        catch (error) {

            console.error(
                "Phone analysis error:",
                error
            );


            return res.status(500).json({

                ok: false,

                error:
                    error?.message ||
                    "Phone number analysis failed."

            });

        }

    }
);


/* =========================================================
   PHONE VALIDATION
========================================================= */

app.post(
    "/api/phone-validate",
    (req, res) => {

        try {

            const body =
                req.body || {};


            const phone =
                body.phone ||
                body.phoneNumber ||
                body.number;


            const country =
                body.country ||
                "IN";


            if (!phone) {

                return res.status(400).json({

                    ok: false,

                    error:
                        "Phone number is required."

                });

            }


            const defaultCountry =
                typeof country === "string" &&
                /^[A-Z]{2}$/i.test(
                    country
                )
                    ? country.toUpperCase()
                    : "IN";


            let lengthResult;


            try {

                lengthResult =
                    validatePhoneNumberLength(
                        phone,
                        defaultCountry
                    );

            }

            catch {

                lengthResult =
                    "INVALID";

            }


            const phoneNumber =
                parsePhoneNumberFromString(
                    phone,
                    defaultCountry
                );


            if (!phoneNumber) {

                return res.json({

                    ok: true,

                    valid: false,

                    possible: false,

                    reason:
                        lengthResult ||
                        "Unable to parse number."

                });

            }


            return res.json({

                ok: true,

                valid:
                    phoneNumber.isValid(),

                possible:
                    phoneNumber.isPossible(),

                country:
                    phoneNumber.country ||
                    null,

                callingCode:
                    phoneNumber.countryCallingCode
                        ? `+${phoneNumber.countryCallingCode}`
                        : null,

                internationalFormat:
                    phoneNumber.formatInternational(),

                nationalFormat:
                    phoneNumber.formatNational(),

                e164:
                    phoneNumber.number

            });

        }

        catch (error) {

            return res.status(500).json({

                ok: false,

                error:
                    error?.message ||
                    "Phone validation failed."

            });

        }

    }
);


/* =========================================================
   GET PHONE CHECK
========================================================= */

app.get(
    "/api/phone-check",
    (req, res) => {

        const phone =
            req.query.phone;


        if (!phone) {

            return res.status(400).json({

                ok: false,

                error:
                    "Use /api/phone-check?phone=%2B919876543210"

            });

        }


        try {

            const result =
                analyzePhone(
                    phone,
                    "IN"
                );


            return res.json(
                result
            );

        }

        catch (error) {

            return res.status(500).json({

                ok: false,

                error:
                    error?.message ||
                    "Phone analysis failed."

            });

        }

    }
);


/* =========================================================
   UNKNOWN API ROUTES
========================================================= */

app.use(
    "/api",
    (req, res) => {

        res.status(404).json({

            ok: false,

            error:
                "Phone API endpoint not found."

        });

    }
);


/* =========================================================
   GENERAL ERROR
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            "Server error:",
            error
        );


        res.status(500).json({

            ok: false,

            error:
                "Internal server error."

        });

    }
);


/* =========================================================
   START
========================================================= */

app.listen(
    PORT,
    () => {

        console.log("");

        console.log(
            "========================================"
        );

        console.log(
            "   SAFNEX NOVA PHONE DETECTOR"
        );

        console.log(
            "========================================"
        );

        console.log("");

        console.log(
            `Phone server: http://localhost:${PORT}`
        );

        console.log(
            `Health:       http://localhost:${PORT}/api/health`
        );

        console.log(
            `Phone API:    http://localhost:${PORT}/api/phone-check`
        );

        console.log("");

        console.log(
            "Link detector is NOT used by this server."
        );

        console.log(
            "========================================"
        );

        console.log("");

    }
);