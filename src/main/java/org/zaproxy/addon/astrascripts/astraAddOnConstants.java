package org.zaproxy.addon.astrascripts;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.script.ScriptVars;

public class astraAddOnConstants {
    // 1. default regex hashmap for PII
    public static final HashMap<String, String> piiRegexMap =
            new HashMap<String, String>() {
                {
                    put("SSN", "\\b(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\\b");
                    put("EMAIL", "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b");
                    put("PANNumber", "\\b[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]\\b");
                    put(
                            "CardNumber",
                            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})\\b");
                }
            };

    public static final HashMap<String, String> jwtAlgos =
            new HashMap<String, String>() {
                {
                    put("HS256", "HmacSHA256");
                    put("HS384", "HmacSHA384");
                    put("HS512", "HmacSHA512");
                }
            };

    private static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static String jwtSigner(String data, String secret, String algo) {
        try {

            byte[] hash = secret.getBytes(StandardCharsets.UTF_8);
            Mac sha256Hmac = Mac.getInstance(jwtAlgos.get(algo));
            SecretKeySpec secretKey = new SecretKeySpec(hash, jwtAlgos.get(algo));
            sha256Hmac.init(secretKey);

            byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));

            return encode(signedBytes);
        } catch (Exception ex) {
            return null;
        }
    }

    // 2. check 404 function with eliminating the false positives.
    public static boolean is404status(HttpMessage msg) {
        String responsebody = msg.getResponseBody().toString();
        String responsebody404 = ScriptVars.getGlobalCustomVar("404HttpMessage").toString();
        if (ScriptVars.getGlobalVar("is404Enabled").equals("False")) {
            double ratio = levenshteinDistanceRatio(responsebody, responsebody404);
            if (ratio <= 0.10) {
                return true;
            } else {
                return false;
            }
        } else {
            if (msg.getResponseHeader().getStatusCode() == 404) {
                return true;
            } else {
                return false;
            }
        }
    }

    // Checks if the response is Html content or not
    public static boolean isHtmlResponse(HttpMessage requestmsg) {
        String responseBody = requestmsg.getResponseBody().toString();
        String regex = "<\\/?[a-z][\\s\\S]*>";
        Matcher matcher = Pattern.compile(regex).matcher(responseBody);
        return matcher.find();
    }

    // utility for #2: compare two strings function and return ratio
    public static double levenshteinDistanceRatio(String str1, String str2) {
        int distance = levenshteinDistance(str1, str2);
        int maxLength = Math.max(str1.length(), str2.length());
        return (double) distance / maxLength;
    }

    // utility for #2: actual function which compares it
    public static int levenshteinDistance(String str1, String str2) {
        int m = str1.length();
        int n = str2.length();

        int[][] dp = new int[m + 1][n + 1];
        for (int i = 0; i <= m; i++) {
            for (int j = 0; j <= n; j++) {
                if (i == 0) {
                    dp[i][j] = j;
                } else if (j == 0) {
                    dp[i][j] = i;
                } else {
                    dp[i][j] =
                            Math.min(
                                    dp[i - 1][j - 1]
                                            + (str1.charAt(i - 1) == str2.charAt(j - 1) ? 0 : 1),
                                    Math.min(dp[i][j - 1] + 1, dp[i - 1][j] + 1));
                }
            }
        }

        return dp[m][n];
    }
}
