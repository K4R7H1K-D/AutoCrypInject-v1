import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.nio.file.StandardCopyOption;

public class ApkAssetProcessor {
    private static final String APKTOOL_PATH = "apktool.jar";
    private static final String OUTPUT_DIR = "Output";
    private static final byte[] AES_KEY = hexStringToByteArray("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    private static final int AES_BLOCK_SIZE = 16;
    private static final List<String> selectedAssets = new ArrayList<>();

    public static void decodeApk(String apkPath, String outputDir) throws IOException {
        System.out.println("[+] Decoding APK: " + apkPath);
        ProcessBuilder pb = new ProcessBuilder("java", "-jar", APKTOOL_PATH, "d", "-f", apkPath, "-o", outputDir);
        pb.inheritIO();
        try {
            Process process = pb.start();
            process.waitFor();
        } catch (InterruptedException e) {
            throw new IOException("Failed to decode APK", e);
        }
        System.out.println("[+] APK decoded to: " + outputDir);
    }

    public static void collectAndEncryptAssets(String assetDir) throws Exception {
        List<String> assetList = new ArrayList<>();

  
        Files.walk(Paths.get(assetDir))
            .filter(Files::isRegularFile)
            .forEach(path -> {
                String relPath = Paths.get(assetDir).relativize(path).toString().replace("\\", "/");
                assetList.add(relPath);
            });

        System.out.println("[*] Available assets:");
        for (String asset : assetList) {
            System.out.println("- " + asset);
        }

        
        System.out.print("[?] Enter asset filenames to encrypt (comma-separated or 'all'): ");
        Scanner scanner = new Scanner(System.in);
        String userInput = scanner.nextLine().trim();

        if (userInput.equalsIgnoreCase("all")) {
            selectedAssets.clear();
            selectedAssets.addAll(assetList);
            System.out.println("[+] All " + selectedAssets.size() + " assets selected for encryption.");
        } else {
            selectedAssets.clear();
            for (String name : userInput.split(",")) {
                String trimmed = name.trim();
                if (!trimmed.isEmpty() && assetList.contains(trimmed)) {
                    selectedAssets.add(trimmed);
                }
            }
            System.out.println("[+] " + selectedAssets.size() + " valid asset(s) selected for encryption.");
        }

        if (selectedAssets.isEmpty()) {
            System.out.println("[!] No valid assets selected. Exiting.");
            System.exit(1);
        }

        
        for (String relPath : selectedAssets) {
            Path filePath = Paths.get(assetDir, relPath);
            if (Files.exists(filePath)) {
                byte[] data = Files.readAllBytes(filePath);

                // Generate random IV
                byte[] iv = new byte[AES_BLOCK_SIZE];
                SecureRandom random = new SecureRandom();
                random.nextBytes(iv);

                // Initialize AES cipher
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

                // Encrypt and prepend IV
                byte[] encrypted = cipher.doFinal(pad(data));
                byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
                System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
                System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

                // Write encrypted file
                Files.write(filePath, encryptedWithIv);
                System.out.println("[+] Encrypted: " + filePath);
                System.out.println("[*] IV: " + bytesToHex(iv));
            } else {
                System.out.println("[!] Asset not found: " + filePath);
            }
        }
    }

    private static byte[] pad(byte[] data) {
        int blockSize = AES_BLOCK_SIZE;
        int paddingLength = blockSize - (data.length % blockSize);
        byte[] padded = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }
        return padded;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static void generateEncryptedRegistryJava(String outputDir, byte[] aesKey) throws IOException {
        if (selectedAssets.isEmpty()) {
            System.out.println("[!] No encrypted assets to add to registry.");
            return;
        }

        if (aesKey == null) {
            System.out.println("[!] AES_KEY is required for decryption.");
            return;
        }

        Files.createDirectories(Paths.get(outputDir));

        String aesKeyHex = bytesToHex(aesKey);
        StringBuilder javaCode = new StringBuilder();
        javaCode.append("package com.decryptassetmanager;\n\n")
                .append("import android.content.Context;\n")
                .append("import android.content.res.AssetManager;\n")
                .append("import android.content.res.AssetFileDescriptor;\n")
                .append("import android.os.ParcelFileDescriptor;\n\n")
				.append("import android.util.Log;\n\n")
                .append("import javax.crypto.Cipher;\n")
                .append("import javax.crypto.spec.IvParameterSpec;\n")
                .append("import javax.crypto.spec.SecretKeySpec;\n\n")
                .append("import java.io.ByteArrayInputStream;\n")
                .append("import java.io.File;\n")
                .append("import java.io.FileOutputStream;\n")
                .append("import java.io.InputStream;\n")
                .append("import java.nio.charset.StandardCharsets;\n")
                .append("import java.util.HashSet;\n")
                .append("import java.util.Set;\n\n")
				.append("import javax.crypto.CipherInputStream;\n\n")
                .append("public class EncryptedAssetRegistry {\n")
                .append("    private static final Set<String> encryptedFiles = new HashSet<>();\n")
                .append("    private static final byte[] AES_KEY = hexStringToByteArray(\"").append(aesKeyHex).append("\");\n\n")
                .append("    static {\n");

        for (String filename : selectedAssets) {
            javaCode.append("        encryptedFiles.add(\"").append(filename).append("\");\n");
        }

        javaCode.append("    }\n\n")
                .append("    public static boolean isEncrypted(String filename) {\n")
				.append("        return encryptedFiles.contains(filename);\n")
				.append("    }\n\n")
				.append("    public static InputStream open(AssetManager assetManager, String filename) throws Exception {\n")
				.append("        if (isEncrypted(filename)) {\n")
				.append("            return openEncryptedAsset(assetManager, filename);\n")
				.append("        } else {\n")
				.append("            return assetManager.open(filename);\n")
				.append("        }\n")
				.append("    }\n\n")
				.append("    public static AssetFileDescriptor openFd(Context context, AssetManager assetManager, String filename) throws Exception {\n")
				.append("        if (isEncrypted(filename)) {\n")
				.append("            return openEncryptedAssetFd(context, assetManager, filename);\n")
				.append("        } else {\n")
				.append("            return assetManager.openFd(filename);\n")
				.append("        }\n")
				.append("    }\n\n")
				.append("    public static InputStream openEncryptedAsset(AssetManager assetManager, String filename) throws Exception {\n")
				.append("        Log.d(\"EncryptedAsset\", \"Starting decryption of \" + filename);\n")
				.append("        long start = System.currentTimeMillis();\n")
				.append("        InputStream is = assetManager.open(filename);\n")			
				.append("        byte[] iv = new byte[16];\n")
				.append("        if (is.read(iv) != 16) throw new Exception(\"Failed to read IV\");\n")				
				.append("        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, \"AES\");\n")
				.append("        IvParameterSpec ivSpec = new IvParameterSpec(iv);\n")
				.append("        Cipher cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n")
				.append("        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);\n")
				.append("        CipherInputStream cis = new CipherInputStream(is, cipher);\n")
				.append("        long end = System.currentTimeMillis();\n")
				.append("        Log.d(\"EncryptedAsset\", \"Decryption completed in \" + (end - start) + \" ms\");\n")
				.append("        return cis;\n")
				.append("    }\n\n")
				.append("    public static AssetFileDescriptor openEncryptedAssetFd(Context context, AssetManager assetManager, String filename) throws Exception {\n")
				.append("        Log.d(\"EncryptedAsset\", \"Starting decryption to temp file: \" + filename);\n")
				.append("        long start = System.currentTimeMillis();\n")
				.append("        InputStream is = assetManager.open(filename);\n")
				.append("        byte[] iv = new byte[16];\n")
			    .append("        if (is.read(iv) != 16) throw new Exception(\"Failed to read IV\");\n")
				.append("        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, \"AES\");\n")
				.append("        IvParameterSpec ivSpec = new IvParameterSpec(iv);\n")
				.append("        Cipher cipher = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n")
				.append("        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);\n")
				.append("        File tempFile = File.createTempFile(\"dec_\", \"_\" + filename.replace(\"/\", \"_\"), context.getCacheDir());\n")
				.append("        try (\n")
				.append("            CipherInputStream cis = new CipherInputStream(is, cipher);\n")
				.append("            FileOutputStream fos = new FileOutputStream(tempFile)\n")
				.append("        ) {\n")
				.append("            byte[] buffer = new byte[4096];\n")
				.append("            int bytesRead;\n")
				.append("            while ((bytesRead = cis.read(buffer)) != -1) {\n")
				.append("                fos.write(buffer, 0, bytesRead);\n")
                .append("            }\n")
                .append("        }\n")				
				.append("        long end = System.currentTimeMillis();\n")
				.append("        Log.d(\"EncryptedAsset\", \"Decryption to file completed in \" + (end - start) + \" ms\");\n")
				.append("        ParcelFileDescriptor pfd = ParcelFileDescriptor.open(tempFile, ParcelFileDescriptor.MODE_READ_ONLY);\n")
				.append("        return new AssetFileDescriptor(pfd, 0, tempFile.length());\n")
				.append("    }\n\n")
				.append("    private static byte[] hexStringToByteArray(String s) {\n")
				.append("        int len = s.length();\n")
				.append("        byte[] data = new byte[len / 2];\n")
				.append("        for (int i = 0; i < len; i += 2) {\n")
				.append("            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));\n")
				.append("        }\n")
				.append("        return data;\n")
				.append("    }\n")
				.append("}\n");

        Path javaPath = Paths.get(outputDir, "EncryptedAssetRegistry.java");
        Files.write(javaPath, javaCode.toString().getBytes(StandardCharsets.UTF_8), StandardOpenOption.CREATE);
        System.out.println("[+] Generated Java class with decryption: " + javaPath);
    }

    public static void convertJavaToSmaliAndInject(String javaFilePath, String androidJarPath, String d8BatPath, String baksmaliJarPath, String smaliOutDir, String decodedApkDir) throws IOException, InterruptedException {
        Path javaFile = Paths.get(javaFilePath).toAbsolutePath();
        String classFile = javaFilePath.replace(".java", ".class");
        String className = Paths.get(classFile).getFileName().toString();

        if (!Files.exists(javaFile)) {
            System.out.println("[!] Java file not found: " + javaFile);
            return;
        }

        System.out.println("[*] Compiling Java file...");
        ProcessBuilder pb = new ProcessBuilder("javac", "-cp", androidJarPath, javaFile.toString());
        pb.inheritIO();
        Process process = pb.start();
        process.waitFor();

        if (!Files.exists(Paths.get(classFile))) {
            System.out.println("[!] Compilation failed, .class file not found.");
            return;
        }

        System.out.println("[*] Converting .class to .dex using d8...");
        pb = new ProcessBuilder(d8BatPath, "--classpath", androidJarPath, classFile, "--output", javaFile.getParent().toString());
        pb.inheritIO();
        process = pb.start();
        process.waitFor();

        Path dexFile = Paths.get(javaFile.getParent().toString(), "classes.dex");
        if (!Files.exists(dexFile)) {
            System.out.println("[!] DEX file not generated: " + dexFile);
            return;
        }

        System.out.println("[*] Disassembling .dex to .smali...");
        Path smaliOutPath = Paths.get(smaliOutDir);
        if (Files.exists(smaliOutPath)) {
            Files.walk(smaliOutPath)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        }
        pb = new ProcessBuilder("java", "-jar", baksmaliJarPath, "disassemble", dexFile.toString(), "--output", smaliOutDir);
        pb.inheritIO();
        process = pb.start();
        process.waitFor();

        Path smaliComDir = Paths.get(smaliOutDir, "com");
        Path targetDir = Paths.get(decodedApkDir, "smali", "com");
        Files.createDirectories(targetDir);

        Files.walk(smaliComDir)
                .filter(Files::isRegularFile)
                .forEach(src -> {
                    try {
                        Path relPath = smaliComDir.relativize(src);
                        Path dst = targetDir.resolve(relPath);
                        Files.createDirectories(dst.getParent());
                        Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING);
                    } catch (IOException e) {
                        System.err.println("[!] Error copying smali file: " + e);
                    }
                });
        System.out.println("[+] Injected smali files into: " + targetDir);
    }

    public static void findAndPatchAssetOpen(String decompiledApkDir) throws IOException {
        Pattern pattern = Pattern.compile("(invoke-\\w+)\\s+(\\{[^\\}]+\\}),\\s*Landroid/content/res/AssetManager;->open\\(Ljava/lang/String;\\)Ljava/io/InputStream;");

        Files.walk(Paths.get(decompiledApkDir))
                .filter(path -> path.toString().contains("smali") && path.toString().replace("\\", "/").contains("/com/") && path.toString().endsWith(".smali"))
                .forEach(filePath -> {
                    try {
                        List<String> lines = Files.readAllLines(filePath);
                        boolean patched = false;

                        for (int i = 0; i < lines.size(); i++) {
                            Matcher matcher = pattern.matcher(lines.get(i));
                            if (matcher.find()) {
                                String invokeType = matcher.group(1);
                                String registers = matcher.group(2).replaceAll("[{}]", "");
                                System.out.println("[FOUND] In file: " + filePath);
                                System.out.println("Line " + (i + 1) + ": " + lines.get(i).trim());

                                String patchedLine = String.format("invoke-static {%s}, Lcom/decryptassetmanager/EncryptedAssetRegistry;->open(Landroid/content/res/AssetManager;Ljava/lang/String;)Ljava/io/InputStream;\n", registers);
                                lines.set(i, patchedLine);
                                patched = true;
                            }
                        }

                        if (patched) {
                            Files.write(filePath, String.join("\n", lines).getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
                            System.out.println("[+] Patched " + filePath + "\n");
                        }
                    } catch (IOException e) {
                        System.err.println("Error processing " + filePath + ": " + e);
                    }
                });
    }

    public static void scanAndPatchOpenFd(String decompiledApkDir) throws IOException {
        Pattern pattern = Pattern.compile("(invoke-\\w+)\\s+\\{([^\\}]+)\\},\\s*Landroid/content/res/AssetManager;->openFd\\(Ljava/lang/String;\\)Landroid/content/res/AssetFileDescriptor;");

        Files.walk(Paths.get(decompiledApkDir))
                .filter(path -> path.toString().contains("smali") && path.toString().replace("\\", "/").contains("/com/") && path.toString().endsWith(".smali"))
                .forEach(filePath -> {
                    try {
                        List<String> lines = Files.readAllLines(filePath);
                        String smaliContent = String.join("\n", lines);
                        boolean patched = false;

                        for (int i = 0; i < lines.size(); i++) {
                            Matcher matcher = pattern.matcher(lines.get(i));
                            if (matcher.find()) {
                                String invokeType = matcher.group(1);
                                String registerStr = matcher.group(2);
                                String[] registers = registerStr.split(",");
                                if (registers.length != 2) continue;

                                String assetManagerReg = registers[0].trim();
                                String assetNameReg = registers[1].trim();

                                String currentClass = filePath.toString().replace(decompiledApkDir, "").replace(File.separator, "/").replace(".smali", "");
                                currentClass = "L" + currentClass.substring(1) + ";";

                                String methodSignature = null;
                                for (int j = i; j >= 0; j--) {
                                    if (lines.get(j).trim().startsWith(".method")) {
                                        methodSignature = lines.get(j).trim();
                                        break;
                                    }
                                }
                                if (methodSignature == null) continue;

                                String ctxReg = findContextRegister(currentClass, methodSignature, smaliContent, smaliContent.indexOf(lines.get(i)), assetManagerReg);
                                if (ctxReg == null) continue;

                                System.out.println("[FOUND] In file: " + filePath);
                                System.out.println("Line " + (i + 1) + ": " + lines.get(i).trim());

                                String patchedLine = String.format("invoke-static {%s, %s, %s}, Lcom/decryptassetmanager/EncryptedAssetRegistry;->openFd(Landroid/content/Context;Landroid/content/res/AssetManager;Ljava/lang/String;)Landroid/content/res/AssetFileDescriptor;\n", ctxReg, assetManagerReg, assetNameReg);
                                lines.set(i, patchedLine);
                                patched = true;
                            }
                        }

                        if (patched) {
                            Files.write(filePath, String.join("\n", lines).getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
                            System.out.println("[+] Patched openFd " + filePath + "\n");
                        }
                    } catch (IOException e) {
                        System.err.println("Error processing " + filePath + ": " + e);
                    }
                });
    }

    private static String findContextRegister(String smaliClass, String smaliMethodSignature, String smaliContent, int startPos, String assetRegister) {
        if (smaliClass.contains("Landroid/app/Activity;") ||
                smaliClass.contains("Landroidx/appcompat/app/AppCompatActivity;") ||
                smaliClass.contains("Landroid/app/Service;") ||
                smaliClass.contains("Landroid/content/Context;")) {
            return "p0";
        }

        String[] methodParams = smaliMethodSignature.split("\\)")[0].replace("(", "").split(";");
        for (int i = 0; i < methodParams.length; i++) {
            if (methodParams[i].contains("Landroid/content/Context")) {
                return "p" + i;
            }
        }

        String[] lines = smaliContent.substring(0, startPos).split("\n");
        for (int i = lines.length - 1; i >= 0; i--) {
            String line = lines[i].trim();
            if (line.startsWith("invoke-virtual") && line.contains("->getAssets()")) {
                Matcher matcher = Pattern.compile("\\{([^}]+)\\}").matcher(line);
                if (matcher.find()) {
                    String[] regs = matcher.group(1).split(",");
                    if (regs.length > 0) {
                        return regs[0].trim();
                    }
                }
            }
        }
        return null;
    }

    public static void recompileApk(String outputDir, String outputApk) throws IOException, InterruptedException {
        System.out.println("[*] Recompiling APK...");
        ProcessBuilder pb = new ProcessBuilder("java", "-jar", APKTOOL_PATH, "b", outputDir, "-o", outputApk);
        pb.inheritIO();
        Process process = pb.start();
        process.waitFor();
        System.out.println("[+] Recompiled APK saved at: " + outputApk);
    }

    public static void signApkWithUber(String apkPath, String uberJarPath) throws IOException, InterruptedException {
        if (!Files.exists(Paths.get(apkPath))) {
            throw new FileNotFoundException("[-] APK not found: " + apkPath);
        }
        if (!Files.exists(Paths.get(uberJarPath))) {
            throw new FileNotFoundException("[-] Uber APK Signer jar not found: " + uberJarPath);
        }

        System.out.println("[*] Signing APK using Uber APK Signer...");
        ProcessBuilder pb = new ProcessBuilder("java", "-jar", uberJarPath, "--apks", apkPath);
        pb.inheritIO();
        Process process = pb.start();
        int exitCode = process.waitFor();
        if (exitCode == 0) {
            System.out.println("[+] APK signed successfully.");
        } else {
            System.out.println("[-] Failed to sign APK.");
        }
    }

    public static void main(String[] args) {
        if (args.length != 1) {
            System.out.println("Usage: java ApkAssetProcessor <apk_file>");
            return;
        }

        try {
            String outputDir = "decoded_apk";
            decodeApk(args[0], outputDir);
            Path assetDir = Paths.get(outputDir, "assets");

            if (!Files.exists(assetDir)) {
                System.out.println("[-] No assets/ folder found.");
                return;
            }

            collectAndEncryptAssets(assetDir.toString());
            findAndPatchAssetOpen("decoded_apk");
            scanAndPatchOpenFd("decoded_apk");
            generateEncryptedRegistryJava("temp_java", AES_KEY);
            convertJavaToSmaliAndInject("temp_java/EncryptedAssetRegistry.java", "android.jar", ".\\d8-35.0.0\\d8.bat", "baksmali-3.0.9-fat.jar", "smali_out", "decoded_apk");
                                                                                                     
            Files.createDirectories(Paths.get(OUTPUT_DIR));
            String outputApk = Paths.get(OUTPUT_DIR, "recompiled_app.apk").toString();
            recompileApk(outputDir, outputApk);

            signApkWithUber(outputApk, "uber-apk-signer-1.3.0.jar");
        } catch (Exception e) {
            System.err.println("[-] Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}