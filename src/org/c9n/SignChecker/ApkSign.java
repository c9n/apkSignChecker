package org.c9n.SignChecker;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ApkSign {

    public static String getApkSignInfo(String apkFilePath) {
        byte[] readBuffer = new byte[8192];
        Certificate[] certs = null;

        try {
            JarFile jarFile = new JarFile(apkFilePath);
            Enumeration entries = jarFile.entries();

            while (entries.hasMoreElements()) {
                JarEntry je = (JarEntry) entries.nextElement();

                if (je.isDirectory() || je.getName().startsWith("META-INF/")) {
                    continue;
                }

                Certificate[] localCerts = loadCertificates(jarFile, je, readBuffer);

                if (certs == null) {
                    certs = localCerts;

                } else {

                    for (Certificate cert : certs) {
                        boolean found = false;

                        for (Certificate localCert : localCerts) {
                            if (cert != null && cert.equals(localCert)) {
                                found = true;
                                break;
                            }
                        }

                        if (!found || certs.length != localCerts.length) {
                            jarFile.close();

                            return null;
                        }
                    }
                }

                jarFile.close();

                return new String(toChars(certs[0].getEncoded()));
            }

            return null;

        } catch (Exception e) {
            // apk 解析出错，直接返回null
            return null;
        }
    }

    private static Certificate[] loadCertificates(JarFile jarFile, JarEntry je,
                                                  byte[] readBuffer) {
        try {
            InputStream is = jarFile.getInputStream(je);
            while (is.read(readBuffer, 0, readBuffer.length) != -1) {

            }
            is.close();
            return je != null ? je.getCertificates() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static char[] toChars(byte[] mSignature) {
        final int N;
        N = mSignature.length;
        final int N2 = N * 2;
        char[] text = new char[N2];

        for (int j = 0; j < N; j++) {
            byte v = mSignature[j];
            int d = (v >> 4) & 0xf;
            text[j * 2] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
            d = v & 0xf;
            text[j * 2 + 1] = (char) (d >= 10 ? ('a' + d - 10) : ('0' + d));
        }
        return text;
    }

    public static String stringToMD5(String str) {
        byte[] hash;

        try {
            hash = MessageDigest.getInstance("MD5").digest(str.getBytes("UTF-8"));
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (UnsupportedEncodingException e) {
            return null;
        }

        StringBuilder hex = new StringBuilder(hash.length * 2);

        for (byte b : hash) {
            if ((b & 0xFF) < 0x10)
                hex.append("0");
            hex.append(Integer.toHexString(b & 0xFF));
        }

        return hex.toString();
    }
}
