document.addEventListener('DOMContentLoaded', () => {
    const encryptBtn = document.getElementById('encrypt-btn');
    const decryptBtn = document.getElementById('decrypt-btn');

    const validateInput = (input, key, iv) => {
        if (!input || input.trim() === '') {
            alert('Input cannot be empty.');
            return false;
        }
        if (!key || key.length !== 32) {
            alert('Key must be 32 characters long.');
            return false;
        }
        if (!iv || iv.length !== 16) {
            alert('IV must be 16 characters long.');
            return false;
        }
        return true;
    };

    const encrypt = async (text, key, iv) => {
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(key),
            { name: 'AES-CBC' },
            false,
            ['encrypt']
        );
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: encoder.encode(iv) },
            cryptoKey,
            data
        );
        return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    };

    const decrypt = async (encryptedText, key, iv) => {
        const decoder = new TextDecoder();
        const encryptedData = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(key),
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: new TextEncoder().encode(iv) },
            cryptoKey,
            encryptedData
        );
        return decoder.decode(decrypted);
    };

    encryptBtn.addEventListener('click', async () => {
        const input = document.getElementById('encrypt-input').value;
        const key = document.getElementById('encrypt-key').value;
        const iv = document.getElementById('encrypt-iv').value;

        if (validateInput(input, key, iv)) {
            try {
                const encrypted = await encrypt(input, key, iv);
                document.getElementById('encrypt-output').value = encrypted;
            } catch (error) {
                alert('Encryption failed: ' + error.message);
            }
        }
    });

    decryptBtn.addEventListener('click', async () => {
        let input = document.getElementById('decrypt-input').value;
        const key = document.getElementById('decrypt-key').value;
        const iv = document.getElementById('decrypt-iv').value;

        if (validateInput(input, key, iv)) {
            // Remove double quotes, single quotes, and commas from the input
            input = input.replace(/["',]/g, '');

            try {
                const decrypted = await decrypt(input, key, iv);
                try {
                    const json = JSON.parse(decrypted);
                    document.getElementById('decrypt-output').value = JSON.stringify(json, null, 4); // Format JSON
                } catch (e) {
                    document.getElementById('decrypt-output').value = decrypted; // Not JSON, display as is
                }
            } catch (error) {
                alert('Decryption failed: ' + error.message);
            }
        }
    });
});
