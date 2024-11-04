const crypto = require("crypto");

function deriveKey(masterPassword) {
    return crypto.createHash("sha256").update(masterPassword).digest();
}

function encrypt(text, masterPassword) {
    const key = deriveKey(masterPassword);
    const iv = crypto.randomBytes(16); 
    const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
    let encrypted = cipher.update(text, "utf8", "base64");
    encrypted += cipher.final("base64");
    
    return {
        encryptedText: encrypted,
        ivBase64: iv.toString("base64"),
    };
}

// Decrypt function using the derived key
function decrypt(encryptedText, masterPassword, ivBase64) {
    if (!encryptedText || !masterPassword || !ivBase64) {
        throw new Error("Missing encryptedText, key, or iv for decryption.");
    }
    
    const key = deriveKey(masterPassword);
    const iv = Buffer.from(ivBase64, "base64"); 
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
    let decrypted = decipher.update(encryptedText, "base64", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

module.exports = { encrypt, decrypt };
