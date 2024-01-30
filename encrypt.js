function base64ArrayBuffer(array) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(array)));
}

function base64ToArrayBuffer(base64) {
    const binary_string = atob(base64);
    const len = binary_string.length;
    let bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

async function encrypt(plaintext, password) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await getKeyMaterial(password, salt);
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 1000, hash: 'SHA-256' },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        enc.encode(plaintext)
    );
    const encryptedArray = new Uint8Array(encrypted);
    let combined = new Uint8Array(salt.length + iv.length + encryptedArray.length);
    combined.set(salt);
    combined.set(iv, salt.length);
    combined.set(encryptedArray, salt.length + iv.length);
    return base64ArrayBuffer(combined);
}

async function decrypt(ciphertext, password) {
    let combined = base64ToArrayBuffer(ciphertext);
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const encrypted = combined.slice(28);
    const keyMaterial = await getKeyMaterial(password, salt);
    const key = await crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 1000, hash: 'SHA-256' },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        encrypted
    );
    return new TextDecoder().decode(decrypted);
}

async function getKeyMaterial(password, salt) {
    const enc = new TextEncoder();
    return crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
}

encrypt("", 1234)
.then(r => {
    console.log(r);
});

decrypt("", 1234)
.then(r => {
    console.log(r);
});
