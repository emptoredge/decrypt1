import { promises as fs } from "fs";
import { createPrivateKey, privateDecrypt, createDecipheriv } from "crypto";

// Optional: Store your private key in Vercel env as PRIVATE_KEY with actual PEM data
const PRIVATE_KEY_PEM = process.env.PRIVATE_KEY;

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method Not Allowed" });
  }
  try {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = req.body;
    if (!encrypted_aes_key || !encrypted_flow_data || !initial_vector) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    // RSA Decrypt AES Key
    const privateKey = createPrivateKey(PRIVATE_KEY_PEM);
    const decryptedAesKey = privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        // WhatsApp uses OAEP, SHA-1 default
      },
      Buffer.from(encrypted_aes_key, "base64")
    );

    // AES Decrypt Flow Data (AES-256-CBC)
    const decipher = createDecipheriv(
      "aes-256-cbc",
      decryptedAesKey,
      Buffer.from(initial_vector, "base64")
    );
    let decrypted = decipher.update(Buffer.from(encrypted_flow_data, "base64"), null, "utf8");
    decrypted += decipher.final("utf8");

    // Try parse as JSON
    let parsed;
    try {
      parsed = JSON.parse(decrypted);
    } catch {
      parsed = null;
    }

    res.status(200).json({ decrypted, json: parsed });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// Vercel (API Routes) expects default export
