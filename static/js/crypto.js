const CryptoUtils = {
    async generateKey() {
        const key = new Uint8Array(32);
        crypto.getRandomValues(key);
        return key;
    },

    async generateIV() {
        const iv = new Uint8Array(12);
        crypto.getRandomValues(iv);
        return iv;
    },

    async importKey(rawKey) {
        return await crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );
    },

    async encrypt(plaintext, key) {
        const iv = await this.generateIV();
        const cryptoKey = await this.importKey(key);
        
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            data
        );

        return {
            ciphertext: new Uint8Array(encrypted),
            iv: iv
        };
    },

    async decrypt(ciphertext, iv, key) {
        const cryptoKey = await this.importKey(key);
        
        try {
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                cryptoKey,
                ciphertext
            );

            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (e) {
            throw new Error('Decryption failed - invalid key or corrupted data');
        }
    },

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    },

    base64ToArrayBuffer(base64) {
        base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = CryptoUtils;
}