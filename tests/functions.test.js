const { encrypt, decrypt } = require("../backend/EncryptionHandler");

describe("Encryption and Decryption Tests", () => {
  const sampleData = "SensitivePassword123!";
  const masterPassword = "secureMasterPassword";
  let encryptedData, iv;

  test("Data should be encrypted and return ciphertext", () => {
    ({ encryptedText: encryptedData, ivBase64: iv } = encrypt(sampleData, masterPassword));

    expect(encryptedData).not.toEqual(sampleData); 
    expect(typeof encryptedData).toBe("string");
    expect(iv).toBeDefined();
  });

  test("Decryption should return the original data with the correct key", () => {
    const decryptedData = decrypt(encryptedData, masterPassword, iv);
    expect(decryptedData).toEqual(sampleData);
  });

  test("Decryption should fail with an incorrect key", () => {
    const incorrectKey = "wrongMasterPassword";
    expect(() => decrypt(encryptedData, incorrectKey, iv)).toThrow();
  });

  test("Decryption should fail with incorrect IV", () => {
    const incorrectIV = iv.slice(1);
    expect(() => decrypt(encryptedData, masterPassword, incorrectIV)).toThrow();
  });
});
