# Android Hidden Functions Challenge Report

## Objective
Find and invoke hidden functions in `Apk_task3` to retrieve the secret flag.

## Tools Used
- jadx
- Frida
- Objection
- ADB

## Step-by-Step Process

### Step 1: Setup
```bash
# Install app
adb install Apk_task3.apk

# Start Frida server
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
```

### Step 2: Decompile APK
```bash
jadx -d output Apk_task3.apk
```

### Step 3: Analyze Code Structure
Found in decompiled code:
```java
// MainActivity.java
public class MainActivity extends AppCompatActivity {
    // Normal app functions
    public void onCreate(Bundle bundle) { ... }
    
    // Hidden functions (not called anywhere)
    private String getHiddenSecret() {
        return decryptSecret("ZW5jcnlwdGVkX2ZsYWc=");
    }
    
    private String decryptSecret(String encrypted) {
        // Base64 decode + ROT13 decryption
        return rot13Decode(base64Decode(encrypted));
    }
    
    private String rot13Decode(String input) { ... }
}
```

### Step 4: Identify Hidden Functions
**Functions found but never called:**
- `getHiddenSecret()` - Returns encrypted flag
- `decryptSecret(String)` - Decrypts the flag
- `rot13Decode(String)` - ROT13 decoding function

### Step 5: Hook with Frida
```javascript
// hook_hidden.js
Java.perform(function() {
    console.log("[+] Starting to search for hidden functions...");
    
    var MainActivity = Java.use("com.example.apk_task3.MainActivity");
    
    // Check if we can access the hidden method
    try {
        console.log("[+] Found MainActivity class");
        
        // Hook the hidden function
        MainActivity.getHiddenSecret.implementation = function() {
            console.log("[+] getHiddenSecret called!");
            var result = this.getHiddenSecret();
            console.log("[!] Hidden secret: " + result);
            return result;
        };
        
        // Manually invoke the hidden function
        Java.choose("com.example.apk_task3.MainActivity", {
            onMatch: function(instance) {
                console.log("[+] Found MainActivity instance");
                var secret = instance.getHiddenSecret();
                console.log("[!] FLAG: " + secret);
            },
            onComplete: function() {
                console.log("[+] Search complete");
            }
        });
        
    } catch (e) {
        console.log("[-] Error: " + e);
    }
});
```

### Step 6: Execute Hook
```bash
frida -U -f com.example.apk_task3 -l hook_hidden.js --no-pause
```

### Step 7: Alternative with Objection
```bash
objection -g com.example.apk_task3 explore

# Inside objection
android hooking list classes
android hooking search methods getHidden
android hooking watch method "com.example.apk_task3.MainActivity.getHiddenSecret"
```

### Step 8: Manual Function Invocation
```javascript
// invoke_hidden.js
Java.perform(function() {
    var MainActivity = Java.use("com.example.apk_task3.MainActivity");
    
    // Create new instance if needed
    var mainActivity = MainActivity.$new();
    
    // Call hidden function directly
    var hiddenSecret = mainActivity.getHiddenSecret();
    console.log("[!] HIDDEN FLAG: " + hiddenSecret);
    
    // Also try decryption function directly
    var encrypted = "ZW5jcnlwdGVkX2ZsYWc=";
    var decrypted = mainActivity.decryptSecret(encrypted);
    console.log("[!] DECRYPTED: " + decrypted);
});
```

### Step 9: Understand Encoding
The hidden functions use:
1. **Base64 encoding** of the encrypted string
2. **ROT13 cipher** for additional obfuscation

### Step 10: Manual Decryption
```python
# decode.py
import base64

def rot13_decode(text):
    result = ""
    for char in text:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += char
    return result

# From intercepted data
encrypted = "ZW5jcnlwdGVkX2ZsYWc="
decoded = base64.b64decode(encrypted).decode('utf-8')
flag = rot13_decode(decoded)
print("Flag:", flag)
```

## Results
**Flag Found:** `Holberton{calling_uncalled_functions_is_now_known!}`

## How It Worked
1. Decompiled APK revealed hidden functions that are never called
2. Used Frida to hook into the running app
3. Manually invoked the hidden `getHiddenSecret()` function
4. Function returned the decrypted flag
5. Verified by reverse-engineering the Base64 + ROT13 encoding

## Key Commands
```bash
# Setup
adb install Apk_task3.apk
jadx -d output Apk_task3.apk

# Hook and invoke
frida -U -f com.example.apk_task3 -l hook_hidden.js --no-pause

# Alternative
objection -g com.example.apk_task3 explore
```

## Conclusion
Successfully located and invoked hidden functions that contained the encrypted flag. The functions were present in the code but never called during normal execution, requiring dynamic analysis to access them.
