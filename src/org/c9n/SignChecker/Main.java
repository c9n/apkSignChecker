package org.c9n.SignChecker;

public class Main {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.exit(1);
        }

        String apk = args[0];
        String certificate = ApkSign.getApkSignInfo(apk);

        if(certificate != null) {
            System.out.println(ApkSign.stringToMD5(certificate));
        } else {
            System.out.println("null");
        }
    }

}
