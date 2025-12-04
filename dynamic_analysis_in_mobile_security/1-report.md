Android Native Function Hooking Report
Objective
Hook into the native function getSecretMessage in the Android app Apk_task1 using Frida to extract the hidden flag.

Tools Used
Frida
ADB
Objection
Step-by-Step Process
Step 1: Setup
bash
# Install the app
adb install Apk_task1.apk

# Start Frida server on device
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
Step 2: Find the App Process
bash
frida-ps -U | grep apk_task1
Step 3: Identify Native Library
The app contains libnative-lib.so which has the target function getSecretMessage.

Step 4: Create Frida Hook Script
javascript
// hook.js
Java.perform(function() {
    console.log("[+] Starting hook...");
    
    // Find the native library
    var lib = Process.findModuleByName("libnative-lib.so");
    
    if (lib) {
        console.log("[+] Found library: " + lib.name);
        
        // Find the target function
        var func = lib.findExportByName("getSecretMessage");
        
        if (func) {
            console.log("[+] Found function at: " + func);
            
            // Hook the function
            Interceptor.attach(func, {
                onLeave: function(retval) {
                    if (!retval.isNull()) {
                        var message = retval.readCString();
                        console.log("[!] SECRET MESSAGE: " + message);
                        
                        if (message.includes("Holberton{")) {
                            console.log("[!] FLAG FOUND: " + message);
                        }
                    }
                }
            });
        }
    }
});
Step 5: Run the Hook
bash
frida -U -f com.example.apk_task1 -l hook.js --no-pause
Step 6: Extract Flag
When the app calls getSecretMessage, Frida intercepts the return value and logs it.

Results
Flag Found: Holberton{native_hooking_is_no_different_at_all}

How It Worked
The app has a native function getSecretMessage that returns a decrypted flag
Frida hooked this function to capture its return value
The function returned the flag as a string
We intercepted and logged this string to get the flag
Key Commands
bash
# Setup
adb install Apk_task1.apk
frida-server &

# Hook
frida -U -f <package> -l hook.js --no-pause

# Monitor logs
adb logcat | grep Holberton
Conclusion
Successfully extracted the hidden flag by hooking the native getSecretMessage function using Frida's Interceptor.attach() method. The flag was processed in native code but captured during runtime analysis.
