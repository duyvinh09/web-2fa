function removeSpaces(input) {
    return input.replace(/\s+/g, '');
}

class GoogleAuthenticator {
    constructor() {
        this._codeLength = 6;
    }

    createSecret(secretLength = 16) {
        const validChars = this._getBase32LookupTable();
        if (secretLength < 16 || secretLength > 128) {
            throw new Error('Bad secret length');
        }
        const array = new Uint8Array(secretLength);
        crypto.getRandomValues(array);
        let secret = '';
        for (let i = 0; i < secretLength; i++) {
            secret += validChars[array[i] & 31];
        }
        return secret;
    }

    getCode(secret, timeSlice = null) {
        if (timeSlice === null) {
            timeSlice = Math.floor(Date.now() / 1000 / 30);
        }

        const secretKey = this._base32Decode(secret);
        if (!secretKey) {
            throw new Error('Invalid secret');
        }

        const timeBuffer = new ArrayBuffer(8);
        const timeView = new DataView(timeBuffer);
        timeView.setUint32(4, timeSlice, false);

        return crypto.subtle.importKey(
            'raw',
            secretKey,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign']
        ).then(key => {
            return crypto.subtle.sign('HMAC', key, timeBuffer);
        }).then(hm => {
            const hmArray = new Uint8Array(hm);
            const offset = hmArray[hmArray.length - 1] & 0x0F;
            const hashPart = hmArray.slice(offset, offset + 4);
            const value = (hashPart[0] << 24 | hashPart[1] << 16 | hashPart[2] << 8 | hashPart[3]) & 0x7FFFFFFF;
            const modulo = Math.pow(10, this._codeLength);
            return String(value % modulo).padStart(this._codeLength, '0');
        });
    }

    setCodeLength(length) {
        this._codeLength = length;
        return this;
    }

    _base32Decode(secret) {
        if (!secret) {
            return '';
        }

        const base32chars = this._getBase32LookupTable();
        const base32charsFlipped = base32chars.reduce((obj, char, i) => ({ ...obj, [char]: i }), {});

        const paddingCharCount = (secret.match(/=/g) || []).length;
        const allowedValues = [6, 4, 3, 1, 0];
        if (!allowedValues.includes(paddingCharCount)) {
            return false;
        }
        for (let i = 0; i < 4; i++) {
            if (paddingCharCount === allowedValues[i] &&
                secret.slice(-allowedValues[i]) !== '='.repeat(allowedValues[i])) {
                return false;
            }
        }

        secret = secret.replace(/=/g, '');
        let binaryString = '';
        for (let i = 0; i < secret.length; i += 8) {
            let x = '';
            if (!base32chars.includes(secret[i])) {
                return false;
            }
            for (let j = 0; j < 8 && (i + j) < secret.length; j++) {
                const charIndex = base32charsFlipped[secret[i + j]];
                if (charIndex === undefined) {
                    return false;
                }
                x += charIndex.toString(2).padStart(5, '0');
            }
            const eightBits = x.match(/.{1,8}/g) || [];
            for (let z = 0; z < eightBits.length; z++) {
                const byte = parseInt(eightBits[z], 2);
                if (byte || byte === 0) {
                    binaryString += String.fromCharCode(byte);
                }
            }
        }

        const result = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            result[i] = binaryString.charCodeAt(i);
        }
        return result;
    }

    _getBase32LookupTable() {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', '2', '3', '4', '5', '6', '7',
            '='
        ];
    }

    timingSafeEquals(safeString, userString) {
        if (safeString.length !== userString.length) {
            return false;
        }
        let result = 0;
        for (let i = 0; i < safeString.length; i++) {
            result |= safeString.charCodeAt(i) ^ userString.charCodeAt(i);
        }
        return result === 0;
    }
}

function reset2FACode() {
    window.location.reload();
}

document.getElementById('toggle-otp').addEventListener('change', function(e) {
    const otpContainer = document.getElementById('otp-container');
    if (this.checked) {
        otpContainer.classList.remove('hidden');
        generateOTP();
        startTimer();
    } else {
        otpContainer.classList.add('hidden');
        clearInterval(timerInterval);
        document.getElementById('timer').textContent = '30';
        document.getElementById('otp-code').value = '';
    }
});

document.getElementById('copy-otp').addEventListener('click', function() {
    const otpInput = document.getElementById('otp-code');
    if (otpInput.value === '') {
        Swal.fire({
            icon: 'error',
            title: 'Lỗi!',
            text: 'Không có mã OTP để sao chép.'
        });
        return;
    }
    otpInput.select();
    document.execCommand('copy');
    
    const originalContent = this.innerHTML;
    this.innerHTML = '<i class="fas fa-check"></i>';
    Swal.fire({
        icon: 'success',
        title: 'Thành công!',
        text: 'Mã OTP đã được sao chép vào clipboard.'
    });
    setTimeout(() => {
        this.innerHTML = originalContent;
    }, 2000);
});

let timerInterval;
function startTimer() {
    let seconds = 30;
    document.getElementById('timer').textContent = seconds;
    
    clearInterval(timerInterval);
    timerInterval = setInterval(() => {
        seconds--;
        document.getElementById('timer').textContent = seconds;
        
        if (seconds <= 0) {
            generateOTP();
            seconds = 30;
            document.getElementById('timer').textContent = seconds;
        }
    }, 1000);
}

function generateOTP() {
    const secretKeyInput = document.getElementById('secret-key');
    const otpInput = document.getElementById('otp-code');
    
    if (secretKeyInput.value.trim() === '') {
        Swal.fire({
            icon: 'error',
            title: 'Lỗi!',
            text: 'Vui lòng nhập mã bí mật trước khi tạo OTP.'
        });
        document.getElementById('toggle-otp').checked = false;
        document.getElementById('otp-container').classList.add('hidden');
        clearInterval(timerInterval);
        document.getElementById('timer').textContent = '30';
        return;
    }

    const sanitizedKey = removeSpaces(secretKeyInput.value.trim());
    const authenticator = new GoogleAuthenticator();

    authenticator.getCode(sanitizedKey).then(code => {
        otpInput.value = code;
    }).catch(error => {
        Swal.fire({
            icon: 'error',
            title: 'Lỗi!',
            text: 'Đã xảy ra lỗi khi tạo mã OTP: ' + error.message
        });
        document.getElementById('toggle-otp').checked = false;
        document.getElementById('otp-container').classList.add('hidden');
        clearInterval(timerInterval);
        document.getElementById('timer').textContent = '30';
        otpInput.value = '';
    });
}