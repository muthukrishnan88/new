import { createWorker } from "tesseract.js";

const worker = await createWorker("eng");

const imagePath = process.argv[2];

if (!imagePath) {
    console.log("Usage:");
    console.log("node ocr-test.js screenshot.png");
    await worker.terminate();
    process.exit(1);
}

console.log("Reading screenshot...");
console.log("OCR started...");

const { data } = await worker.recognize(imagePath);

console.log("\n================================");
console.log("EXTRACTED TEXT");
console.log("================================\n");

console.log(data.text || "(No text detected)");

console.log("\n================================");

await worker.terminate();