import Tesseract from "tesseract.js";
import pdfParse from "pdf-parse";
import { fileTypeFromBuffer } from "file-type";

const URL_REGEX = /https?:\/\/[^\s"')]+/gi;

export async function detectMime(buffer, hintedMime) {
  if (hintedMime) return hintedMime;
  const ft = await fileTypeFromBuffer(buffer);
  return ft?.mime || "application/octet-stream";
}

export async function extractTextFromBuffer(buffer, mimeType) {
  if (mimeType === "application/pdf") {
    const data = await pdfParse(buffer);
    return data.text || "";
  }

  if (mimeType.startsWith("image/")) {
    const result = await Tesseract.recognize(buffer, "eng", {
      logger: () => {}
    });
    return result.data.text || "";
  }

  return "";
}

export function extractUrlsFromText(text) {
  const matches = text.match(URL_REGEX);
  if (!matches) return [];
  return matches.map(u => u.replace(/[),.;]+$/, ""));
}