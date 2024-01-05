const crypto = require('crypto');

function encrypt(text, key) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(text, key) {
    let iv = Buffer.from(text.iv, 'hex');
    let encryptedText = Buffer.from(text.encryptedData, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ініціювання клієнтом
let clientHello = crypto.randomBytes(16).toString('hex');
console.log('Клієнт привіт:', clientHello);

// відповідь сервера (генерація пари ключів)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});
let serverHello = crypto.randomBytes(16).toString('hex');
console.log('Сервер привіт:', serverHello);

// клієнт відсилає зашифрований premaster
let premasterSecret = crypto.randomBytes(16).toString('hex');
let encryptedPremaster = crypto.publicEncrypt(publicKey, Buffer.from(premasterSecret));

// сервер розшифровує premaster
let decryptedPremaster = crypto.privateDecrypt(privateKey, encryptedPremaster);

// генерація сеансових ключів
let sessionKey = crypto.createHash('sha256').update(decryptedPremaster.toString() + clientHello + serverHello).digest('hex');

// готовність клієнта та сервера
let clientReady = encrypt('Клієнт готовий', sessionKey);
let serverReady = encrypt('Сервер готовий', sessionKey);

// завершення рукостискання
console.log('Клієнт готовий (зашифровано):', clientReady);
console.log('Сервер готовий (зашифровано):', serverReady);

// передача даних по захищеному каналу
let message = 'Це таємне повідомлення';
let encryptedMessage = encrypt(message, sessionKey);
console.log('Зашифроване повідомлення:', encryptedMessage);

// дешифрування повідомлення
let decryptedMessage = decrypt(encryptedMessage, sessionKey);
console.log('Дешифроване повідомлення:', decryptedMessage);
