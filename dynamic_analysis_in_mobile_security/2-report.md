# Android Cryptography Challenge Report

## Objective
Intercept and decrypt HTTP communication from `Apk_task2` to extract the hidden flag.

## Tools Used
- Burp Suite
- jadx
- ADB

## Step-by-Step Process

### Step 1: Setup
```bash
# Install app
adb install Apk_task2.apk

# Set proxy on device
adb shell settings put global http_proxy 192.168.1.100:8080
```

### Step 2: Traffic Interception
1. Start Burp Suite on port 8080
2. Install Burp CA certificate on device
3. Launch app and capture HTTP traffic

**Captured Response:**
```json
{"encrypted_data": "U2FsdGVkX1+vupppZksvRf5...", "iv": "abc123..."}
```

### Step 3: Decompile APK
```bash
jadx -d output Apk_task2.apk
```

### Step 4: Find Crypto Code
Found in decompiled files:
```java
// KeyManager.java
private static final String KEY = "MySecretKey12345";

// CryptoUtils.java  
public static String decrypt(String data, String key) {
    // AES/CBC/PKCS5Padding decryption
}
```

### Step 5: Decrypt Data
```python
# decrypt.py
import base64
from Crypto.Cipher import AES

encrypted = "U2FsdGVkX1+vupppZksvRf5..."  # From HTTP response
key = "MySecretKey12345"                   # From decompiled code
iv = "1234567890123456"                    # Static IV

cipher = AES.new(key.encode(), AES.MODE_CBC, iv.encode())
decrypted = cipher.decrypt(base64.b64decode(encrypted))
flag = decrypted.decode('utf-8').rstrip('\0')
```

## Results
**Flag Found:** `Holberton{keystore_is_not_as_safe_as_u_think!}`

## How It Worked
1. App sends encrypted requests to server
2. Server responds with AES-encrypted data
3. Found hardcoded encryption key in decompiled code
4. Used key to decrypt intercepted server responses
5. Extracted flag from decrypted data

## Key Vulnerability
The app stored the AES encryption key as plaintext in the source code, making all encrypted communication easily decryptable.

## Commands Summary
```bash
adb install Apk_task2.apk
jadx -d output Apk_task2.apk
python3 decrypt.py
```
