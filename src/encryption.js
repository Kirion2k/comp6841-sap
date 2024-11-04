import CryptoJS from 'crypto-js';

export const encryptData = (data, key) => {
  const iv = CryptoJS.lib.WordArray.random(16); 
  const encrypted = CryptoJS.AES.encrypt(data, CryptoJS.enc.Utf8.parse(key), {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });
  
  return {
    encryptedData: encrypted.toString(), 
    iv: iv.toString(CryptoJS.enc.Base64) 
  };
};

export const decryptData = (encryptedText, key, ivBase64) => {
  if (!encryptedText || !key || !ivBase64) {
    console.error('Missing encryptedText, key, or iv for decryption:', { encryptedText, key, ivBase64 });
    return null;
  }

  try {
    const iv = CryptoJS.enc.Base64.parse(ivBase64); 
    const decrypted = CryptoJS.AES.decrypt(encryptedText, CryptoJS.enc.Utf8.parse(key), {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7,
    });

    const decryptedData = decrypted.toString(CryptoJS.enc.Utf8);
    console.log(decryptedData);
    if (!decryptedData) {
      console.error('Decryption resulted in empty data. Check the master password or encryption parameters.');
      return null;
    }

    return decryptedData;
  } catch (error) {
    console.error('Decryption failed:', error);
    return null;
  }
};
