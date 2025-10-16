# AutoCrypInject v1.0 : Automated Android Asset Security Framework

### Introduction
`Goal` : **Asset Encryption and Runtine Decryption**
* AutoCrypInject is a framework designed to bolster Android application security by automating the encryption of internal assets. It targets the critical vulnerability of sensitive data being stored as plaintext files within an APK's assets directory. By injecting the necessary runtime decryption logic, the tool raises the barrier against static analysis and reverse engineering.

### Core Features

- **APK Decompilation & Recompilation**: Using Apktool for unpacking and rebuilding of APK files.
- **Selective Asset Encryption**: Allows the user to interactively select specific assets or all assets for encryption using the **AES-256** algorithm.
- **Dynamic Code Generation**: Generate a custom Java decryption module tailored to the selected assets and embedding the necessary cryptographic keys.
- **Smali Code Injection**: Converts the Java decryption module into Smali bytecode and intelligently injects it into the decompiled application's source.
- **Automated Bytecode Patching**: Scans the application's Smali code and automatically patches all invocations of `AssetManager.open()`, `AssetManager.openFd()` to redirect through the injected decryption logic.
- **Automated Signing**: Signs the final, repackaged APK with a debug key for immediate deployment and testing.

### Architectural Flow : [Visual Representation](https://k4r7h1k-d.github.io/AutoCrypInject-v1/)
1. **Decompile**: The process starts with a `Target APK`, which is decompiled into its constituent `Decompiled APK Files`.
2. **Encrypt**: Following a `User Selection` of files to protect, the chosen assets are encrypted, resulting in `Encrypted Assets`.
3. **Generate & Convert**: A `Decryption java source` file is created and converted through the sequence `java` → `class` → `dex` → `smali`.
4. **Patch**: The system scans the decompiled code for asset-loading functions like `open()` and `openFd()` and patches them, creating `Modified functions`.
5. **Inject**: The `Converted Decryption smali` code from step 3 is injected into the modified application code.
6. **Rebuild & Sign**: Finally, the modified project is recompiled into a `Recompiled Secured APK`, which is then put through a `signature & verification` process.


### usage

```jsx
python TOOL_AES.py /path/to/my_app.apk
```

