package org.entur.jwt.spring;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class JwtIssuerClaimExtractor {

    private static final byte DOUBLE_QUOTE = '"';
    private static final byte BACKSLASH = '\\';
    private static final byte OPEN_OBJECT = '{';
    private static final byte CLOSE_OBJECT = '}';
    private static final byte COLON = ':';
    private static final byte ISS_I = 'i';
    private static final byte ISS_S = 's';

    private JwtIssuerClaimExtractor() {
    }

    public static String extractIssuer(String token) {
        if (token == null) {
            return null;
        }

        int firstDot = token.indexOf('.');
        if (firstDot <= 0 || firstDot == token.length() - 1) {
            return null;
        }

        int secondDot = token.indexOf('.', firstDot + 1);
        if (secondDot <= firstDot + 1) {
            return null;
        }

        return extractIssuerFromPayloadSegment(token.substring(firstDot + 1, secondDot));
    }

    static String extractIssuerFromPayloadSegment(String payloadSegment) {
        byte[] payload;
        try {
            payload = Base64.getUrlDecoder().decode(payloadSegment);
        } catch (IllegalArgumentException e) {
            return null;
        }

        int depth = 0;
        int i = 0;
        while (i < payload.length) {
            byte current = payload[i];
            if (current == OPEN_OBJECT) {
                depth++;
                i++;
                continue;
            }
            if (current == CLOSE_OBJECT) {
                depth--;
                i++;
                continue;
            }
            if (current == DOUBLE_QUOTE && depth == 1) {
                int keyStart = i + 1;
                int keyEnd = findStringEnd(payload, keyStart);
                if (keyEnd < 0) {
                    return null;
                }

                if (isIssuerKey(payload, keyStart, keyEnd)) {
                    int separator = skipWhitespace(payload, keyEnd + 1);
                    if (separator >= payload.length || payload[separator] != COLON) {
                        return null;
                    }
                    int valueQuoteStart = skipWhitespace(payload, separator + 1);
                    if (valueQuoteStart >= payload.length || payload[valueQuoteStart] != DOUBLE_QUOTE) {
                        return null;
                    }
                    int valueStart = valueQuoteStart + 1;
                    int valueEnd = findStringEnd(payload, valueStart);
                    if (valueEnd < 0) {
                        return null;
                    }
                    return decodeJsonString(payload, valueStart, valueEnd);
                }

                i = keyEnd + 1;
                continue;
            }
            i++;
        }

        return null;
    }

    private static int skipWhitespace(byte[] payload, int index) {
        int i = index;
        while (i < payload.length) {
            byte c = payload[i];
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                i++;
            } else {
                break;
            }
        }
        return i;
    }

    private static int findStringEnd(byte[] payload, int start) {
        boolean escaping = false;
        for (int i = start; i < payload.length; i++) {
            byte c = payload[i];
            if (escaping) {
                escaping = false;
                continue;
            }
            if (c == BACKSLASH) {
                escaping = true;
            } else if (c == DOUBLE_QUOTE) {
                return i;
            }
        }
        return -1;
    }

    private static boolean isIssuerKey(byte[] payload, int start, int end) {
        return end - start == 3 && payload[start] == ISS_I && payload[start + 1] == ISS_S && payload[start + 2] == ISS_S;
    }

    private static String decodeJsonString(byte[] payload, int start, int end) {
        int firstEscape = -1;
        for (int i = start; i < end; i++) {
            if (payload[i] == BACKSLASH) {
                firstEscape = i;
                break;
            }
        }

        if (firstEscape == -1) {
            return new String(payload, start, end - start, StandardCharsets.UTF_8);
        }

        StringBuilder builder = new StringBuilder(end - start);
        for (int i = start; i < end; i++) {
            byte c = payload[i];
            if (c != BACKSLASH) {
                builder.append((char) c);
                continue;
            }
            if (++i >= end) {
                return null;
            }
            byte escaped = payload[i];
            switch (escaped) {
                case '"':
                case '\\':
                case '/':
                    builder.append((char) escaped);
                    break;
                case 'b':
                    builder.append('\b');
                    break;
                case 'f':
                    builder.append('\f');
                    break;
                case 'n':
                    builder.append('\n');
                    break;
                case 'r':
                    builder.append('\r');
                    break;
                case 't':
                    builder.append('\t');
                    break;
                case 'u':
                    if (i + 4 >= end) {
                        return null;
                    }
                    int codePoint = decodeHex(payload[i + 1], payload[i + 2], payload[i + 3], payload[i + 4]);
                    if (codePoint < 0) {
                        return null;
                    }
                    builder.append((char) codePoint);
                    i += 4;
                    break;
                default:
                    return null;
            }
        }
        return builder.toString();
    }

    private static int decodeHex(byte a, byte b, byte c, byte d) {
        int result = (hexValue(a) << 12) | (hexValue(b) << 8) | (hexValue(c) << 4) | hexValue(d);
        return result < 0 ? -1 : result;
    }

    private static int hexValue(byte value) {
        if (value >= '0' && value <= '9') {
            return value - '0';
        }
        if (value >= 'a' && value <= 'f') {
            return value - 'a' + 10;
        }
        if (value >= 'A' && value <= 'F') {
            return value - 'A' + 10;
        }
        return -1;
    }
}
