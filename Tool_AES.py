import os
import re
import shutil
import subprocess
import sys
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

APKTOOL_PATH = 'apktool.jar'  
OUTPUT_DIR = "Output"
AES_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
AES_BLOCK_SIZE = 16 
selected_assets = []  # Global list to share between functions



def decode_apk(apk_path, output_dir):
    """Decode APK using apktool."""
    print(f"[+] Decoding APK: {apk_path}")
    subprocess.run(["java", "-jar", APKTOOL_PATH, "d", "-f", apk_path, "-o", output_dir], check=True)
    print(f"[+] APK decoded to: {output_dir}")


def collect_and_encrypt_assets(asset_dir):
    global selected_assets
    asset_list = []
    for root, _, files in os.walk(asset_dir):
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), asset_dir)
            asset_list.append(rel_path.replace("\\", "/"))

    print("[*] Available assets:")
    for asset in asset_list:
        print(f"- {asset}")

    user_input = input("[?] Enter asset filenames to encrypt (comma-separated): ")
    if user_input.lower() == "all":
        selected_assets = asset_list
        print(f"[+] All {len(selected_assets)} assets selected for encryption.")
    else:
        selected_assets = [f.strip() for f in user_input.split(",") if f.strip()]
        selected_assets = [f for f in selected_assets if f in asset_list]
        print(f"[+] {len(selected_assets)} valid asset(s) selected for encryption.")

    if not selected_assets:
        print("[!] No valid assets selected. Exiting.")
        exit(1)


    for rel_path in selected_assets:
        filepath = os.path.join(asset_dir, rel_path)
        if os.path.isfile(filepath):
            with open(filepath, "rb") as f:
                data = f.read()
            
            AES_IV = get_random_bytes(AES_BLOCK_SIZE)
            print(AES_IV)
            cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
            encrypted = cipher.encrypt(pad(data, AES_BLOCK_SIZE))
            encrypted_with_iv = AES_IV + encrypted
            with open(filepath, "wb") as f:
                f.write(encrypted_with_iv)
            print(f"[+] Encrypted: {filepath}")
        else:
            print(f"[!] Asset not found: {filepath}")



def generate_encrypted_registry_java(output_dir="temp_java", AES_KEY=None):
    """
    Generates EncryptedAssetRegistry.java containing the list of encrypted assets
    from the `selected_assets` global list with built-in decryption capabilities.
    """
    if not selected_assets:
        print("[!] No encrypted assets to add to registry.")
        return

    if not AES_KEY:
        print("[!] AES_KEY  are required for decryption.")
        return

    os.makedirs(output_dir, exist_ok=True)

    # Convert keys to strings if they're bytes
    aes_key_hex = AES_KEY.hex() if isinstance(AES_KEY, bytes) else AES_KEY

    java_code = [
    "package com.decryptassetmanager;\n\n",
    "import android.content.Context;\n",
    "import android.content.res.AssetManager;\n",
    "import android.content.res.AssetFileDescriptor;\n",
    "import android.os.ParcelFileDescriptor;\n",
    "import android.util.Log;\n\n",
    "import javax.crypto.Cipher;\n",
    "import javax.crypto.spec.IvParameterSpec;\n",
    "import javax.crypto.spec.SecretKeySpec;\n\n",
    "import java.io.ByteArrayInputStream;\n",
    "import java.io.File;\n",
    "import java.io.FileOutputStream;\n",
    "import java.io.InputStream;\n",
    "import java.util.HashSet;\n",
    "import java.util.Set;\n",
    "import javax.crypto.CipherInputStream;\n\n",
    "public class EncryptedAssetRegistry {\n",
    "    private static final Set<String> encryptedFiles = new HashSet<>();\n",
    f"    private static final byte[] AES_KEY = hexStringToByteArray(\"{aes_key_hex}\");\n\n",
    "    static {\n"
]

    # Add encrypted files to the registry
    for filename in selected_assets:
        java_code.append(f'        encryptedFiles.add("{filename}");\n')

    java_code += [
    "    }\n\n",
    "    public static boolean isEncrypted(String filename) {\n",
    "        return encryptedFiles.contains(filename);\n",
    "    }\n\n",
    "    public static InputStream open(AssetManager assetManager, String filename) throws Exception {\n",
    "        if (isEncrypted(filename)) {\n",
    "            return openEncryptedAsset(assetManager, filename);\n",
    "        } else {\n",
    "            return assetManager.open(filename);\n",
    "        }\n",
    "    }\n\n",
    "    public static AssetFileDescriptor openFd(Context context, AssetManager assetManager, String filename) throws Exception {\n",
    "        if (isEncrypted(filename)) {\n",
    "            return openEncryptedAssetFd(context, assetManager, filename);\n",
    "        } else {\n",
    "            return assetManager.openFd(filename);\n",
    "        }\n",
    "    }\n\n",
    "    public static InputStream openEncryptedAsset(AssetManager assetManager, String filename) throws Exception {\n",
    "        Log.d(\"EncryptedAsset\", \"Starting decryption of \" + filename);\n",
    "        long start = System.currentTimeMillis();\n",
    "        InputStream is = assetManager.open(filename);\n",
    "        byte[] iv = new byte[16];\n",
    "        if (is.read(iv) != 16) throw new Exception(\"Failed to read IV\");\n",
    "        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, \"AES\");\n",
    "        IvParameterSpec ivSpec = new IvParameterSpec(iv);\n",
    "        Cipher cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n",
    "        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);\n",
    "        CipherInputStream cis = new CipherInputStream(is, cipher);\n",
    "        long end = System.currentTimeMillis();\n",
    "        Log.d(\"EncryptedAsset\", \"Decryption completed in \" + (end - start) + \" ms\");\n",
    "        return cis;\n",
    "    }\n\n",
    "    public static AssetFileDescriptor openEncryptedAssetFd(Context context, AssetManager assetManager, String filename) throws Exception {\n",
    "        Log.d(\"EncryptedAsset\", \"Starting decryption to temp file: \" + filename);\n",
    "        long start = System.currentTimeMillis();\n",
    "        InputStream is = assetManager.open(filename);\n",
    "        byte[] iv = new byte[16];\n",
    "        if (is.read(iv) != 16) throw new Exception(\"Failed to read IV\");\n",
    "        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, \"AES\");\n",
    "        IvParameterSpec ivSpec = new IvParameterSpec(iv);\n",
    "        Cipher cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n",
    "        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);\n",
    "        File tempFile = File.createTempFile(\"dec_\", \"_\" + filename.replace(\"/\", \"_\"), context.getCacheDir());\n",
    "        try (\n",
    "            CipherInputStream cis = new CipherInputStream(is, cipher);\n",
    "            FileOutputStream fos = new FileOutputStream(tempFile)\n",
    "        ) {\n",
    "            byte[] buffer = new byte[4096];\n",
    "            int bytesRead;\n",
    "            while ((bytesRead = cis.read(buffer)) != -1) {\n",
    "                fos.write(buffer, 0, bytesRead);\n",
    "            }\n",
    "        }\n",
    "        long end = System.currentTimeMillis();\n",
    "        Log.d(\"EncryptedAsset\", \"Decryption to file completed in \" + (end - start) + \" ms\");\n",
    "        ParcelFileDescriptor pfd = ParcelFileDescriptor.open(tempFile, ParcelFileDescriptor.MODE_READ_ONLY);\n",
    "        return new AssetFileDescriptor(pfd, 0, tempFile.length());\n",
    "    }\n\n",
    "    private static byte[] hexStringToByteArray(String s) {\n",
    "        int len = s.length();\n",
    "        byte[] data = new byte[len / 2];\n",
    "        for (int i = 0; i < len; i += 2) {\n",
    "            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)\n",
    "                                 + Character.digit(s.charAt(i+1), 16));\n",
    "        }\n",
    "        return data;\n",
    "    }\n",
    "}\n"
]

    java_path = os.path.join(output_dir, "EncryptedAssetRegistry.java")
    with open(java_path, "w", encoding="utf-8") as f:
        f.writelines(java_code)

    print(f"[+] Generated Java class with decryption: {java_path}")




def convert_java_to_smali_and_inject(
    java_file_path,
    android_jar_path="android.jar",
    d8_bat_path=r".\d8-35.0.0\d8.bat",
    baksmali_jar_path="baksmali-3.0.9-fat.jar",
    smali_out_dir="smali_out",
    decoded_apk_dir="decoded_apk"
):
    # Step 0: Ensure paths and directories
    java_file = os.path.abspath(java_file_path)
    class_file = java_file.replace(".java", ".class")
    class_name = os.path.basename(class_file)
    java_dir = os.path.dirname(java_file)

    if not os.path.exists(java_file):
        print(f"[!] Java file not found: {java_file}")
        return

    # Step 1: Compile .java to .class using javac
    print("[*] Compiling Java file...")
    compile_cmd = [
        "javac", "-cp", android_jar_path, java_file
    ]
    subprocess.run(compile_cmd, check=True)

    if not os.path.exists(class_file):
        print(f"[!] Compilation failed, .class file not found.")
        return

    # Step 2: Convert .class to .dex using d8.bat
    print("[*] Converting .class to .dex using d8...")
    subprocess.run([
        d8_bat_path,
        "--classpath", android_jar_path,
        class_file, "--output", java_dir
    ], check=True)

    dex_file = os.path.join(java_dir, "classes.dex")
    if not os.path.exists(dex_file):
        print(f"[!] DEX file not generated: {dex_file}")
        return

    # Step 3: Convert .dex to .smali using baksmali
    print("[*] Disassembling .dex to .smali...")
    if os.path.exists(smali_out_dir):
        shutil.rmtree(smali_out_dir)
    subprocess.run([
    "java", "-jar", "../baksmali-3.0.9-fat.jar",
    "disassemble", "classes.dex",
    "--output", "../smali_out"], check=True, cwd="temp_java")

    # Step 4: Inject smali into decoded APK
    smali_com_dir = os.path.join(smali_out_dir, "com")
    target_dir = os.path.join(decoded_apk_dir, "smali", "com")
    os.makedirs(target_dir, exist_ok=True)

    def copy_recursive(src, dst):
        for root, dirs, files in os.walk(src):
            for file in files:
                src_file = os.path.join(root, file)
                rel_path = os.path.relpath(src_file, src)
                dst_file = os.path.join(dst, rel_path)
                os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                shutil.copyfile(src_file, dst_file)

    copy_recursive(smali_com_dir, target_dir)
    print(f"[+] Injected smali files into: {target_dir}")



def find_and_patch_asset_open(decompiled_apk_dir):

    pattern = re.compile(r'(invoke-\w+)\s+({[^}]+}),\s*Landroid/content/res/AssetManager;->open\(Ljava/lang/String;\)Ljava/io/InputStream;')
    found_calls = []

    for root, dirs, files in os.walk(decompiled_apk_dir):
        # Scan only smali folders inside com/
        if 'smali' not in root or '/com/' not in root.replace("\\", "/"):
            continue

        for file in files:
            if not file.endswith('.smali'):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                patched = False
                for idx, line in enumerate(lines):
                    match = pattern.search(line)
                    if match:
                        invoke_type, registers = match.groups()
                        print(f"[FOUND] In file: {file_path}")
                        print(f"Line {idx + 1}: {line.strip()}")
                        

                        patched_line = (
                            f"invoke-static {registers}, "
                            f"Lcom/decryptassetmanager/EncryptedAssetRegistry;->open("
                            f"Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/InputStream;\n"
                        )
                        lines[idx] = patched_line
                        patched = True

                if patched:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    print(f"[+] Patched {file_path}\n")

            except Exception as e:
                print(f"Error processing {file_path}: {e}")

def scan_and_patch_open_fd(decompiled_apk_dir):
    pattern = re.compile(
        r'(invoke-\w+)\s+\{([^\}]+)\},\s*Landroid/content/res/AssetManager;->openFd\(Ljava/lang/String;\)Landroid/content/res/AssetFileDescriptor;'
    )
    found_calls = []

    for root, dirs, files in os.walk(decompiled_apk_dir):

        if 'smali' not in root or '/com/' not in root.replace("\\", "/"):
            continue

        for file in files:
            if not file.endswith('.smali'):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()

                smali_content = ''.join(lines)
                patched = False

                for idx, line in enumerate(lines):
                    match = pattern.search(line)
                    if match:
                        invoke_type, register_str = match.groups()
                        registers = [r.strip() for r in register_str.split(',')]
                        if len(registers) != 2:
                            continue

                        assetManager_reg, assetName_reg = registers

                        # --- Extract smali class path ---
                        current_class = file_path.replace(decompiled_apk_dir, '').replace(os.sep, '/').lstrip('/').replace('.smali', '')
                        current_class = f"L{current_class};"

                        # --- Extract method signature ---
                        method_signature = None
                        for rev_idx in range(idx, -1, -1):
                            if lines[rev_idx].strip().startswith('.method'):
                                method_signature = lines[rev_idx].strip()
                                break
                        if method_signature is None:
                            continue 

                        # --- Get context register ---
                        ctx_reg = find_context_register(
                            smali_class=current_class,
                            smali_method_signature=method_signature,
                            smali_content=smali_content,
                            start_pos=smali_content.find(line),
                            asset_register=assetManager_reg
                        )

                        if not ctx_reg:
                            continue 

                        print(f"[FOUND] In file: {file_path}")
                        print(f"Line {idx + 1}: {line.strip()}")

                        
                        patched_line = (
                            f"invoke-static {{{ctx_reg}, {assetManager_reg}, {assetName_reg}}}, "
                            f"Lcom/decryptassetmanager/EncryptedAssetRegistry;->openFd("
                            f"Landroid/content/Context;Landroid/content/res/AssetManager;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;\n"
                        )
                        lines[idx] = patched_line
                        patched = True

                if patched:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    print(f"[+] Patched openFd {file_path}\n")

            except Exception as e:
                print(f"Error processing {file_path}: {e}")


def find_context_register(smali_class, smali_method_signature, smali_content, start_pos, asset_register):
    
    # Step 1: Heuristic Check on Class Type
    if ('Landroid/app/Activity;' in smali_class or
        'Landroidx/appcompat/app/AppCompatActivity;' in smali_class or
        'Landroid/app/Service;' in smali_class or
        'Landroid/content/Context;' in smali_class):
        return 'p0'  # 'p0' usually holds the Context in instance methods

    # Step 2: Method Parameter Check
    method_params = smali_method_signature.split(')')[0].strip('(').split(';')
    method_params = [param for param in method_params if param]  # Remove empty parts
    for idx, param in enumerate(method_params):
        if 'Landroid/content/Context' in param:
            return f'p{idx}'  # Found Context param

    # Step 3: Reverse Trace for getAssets()
    lines = smali_content[:start_pos].splitlines()
    lines.reverse()
    for line in lines:
        line = line.strip()
        if line.startswith("invoke-virtual") and "->getAssets()" in line:
            regs = re.findall(r'\{([^\}]+)\}', line)
            if regs:
                reg_list = [r.strip() for r in regs[0].split(',')]
                if reg_list:
                    return reg_list[0]  # Found Context register

  
    return None



def recompile_apk(output_dir, output_apk):
    print("[*] Recompiling APK...")
    subprocess.run(["java", "-jar", APKTOOL_PATH, "b", output_dir, "-o", output_apk], check=True)
    print(f"[+] Recompiled APK saved at: {output_apk}")


def sign_apk_with_uber(apk_path, uber_jar_path="uber-apk-signer-1.3.0.jar"):
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"[-] APK not found: {apk_path}")
    if not os.path.exists(uber_jar_path):
        raise FileNotFoundError(f"[-] Uber APK Signer jar not found: {uber_jar_path}")

    print("[*] Signing APK using Uber APK Signer...")

    try:
        subprocess.run(
            ["java", "-jar", uber_jar_path, "--apks", apk_path],
            check=True
        )
        print("[+] APK signed successfully.")

    except subprocess.CalledProcessError:
        print("[-] Failed to sign APK.")
        return None






def main(apk_path):
    output_dir = 'decoded_apk'
    decode_apk(apk_path, output_dir)
    asset_dir = os.path.join(output_dir, 'assets')

    if not os.path.exists(asset_dir):
        print("[-] No assets/ folder found.")
        return

    collect_and_encrypt_assets(asset_dir)
    find_and_patch_asset_open('decoded_apk')
    scan_and_patch_open_fd('decoded_apk')
    generate_encrypted_registry_java("temp_java", AES_KEY)
    convert_java_to_smali_and_inject("temp_java/EncryptedAssetRegistry.java")
    
    
    
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_apk = os.path.join(OUTPUT_DIR, "recompiled_app.apk")  
    recompile_apk(output_dir, output_apk)

    signed = sign_apk_with_uber("Output/recompiled_app.apk")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python apk_asset_extractor.py <apk_file>")
    else:
        main(sys.argv[1])