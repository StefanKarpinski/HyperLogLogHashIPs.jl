import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HyperLogLogHashIPs {
    static final int ROUNDS = 16;

    static void feistel(MessageDigest digest, byte key[], byte data[], boolean enc) {
        int n = data.length;
        int m = n >> 1;
        int init = (byte) (enc ? 0 : ROUNDS-1);
        int last = (byte) (enc ? ROUNDS-1 : 0);
        int step = (byte) (enc ? 1 : -1);
        for (int round = init; 0 <= round && round < ROUNDS; round += step) {
            digest.update((byte) round);
            digest.update(key);
            digest.update(data, m, n-m);
            byte x[] = digest.digest();
            for (int i = 0; i < x.length; i++)
                data[i % m] ^= x[i];
            if (round == last) break;
            for (int i = 0; i < m; i++) {
                byte t = data[i];
                data[i] = data[m+i];
                data[m+i] = t;
            }
        }
    }

    static void encrypt(MessageDigest digest, byte key[], byte data[]) {
        feistel(digest, key, data, true);
    }
    static void decrypt(MessageDigest digest, byte key[], byte data[]) {
        feistel(digest, key, data, false);
    }

    static final int ignore_bits = 2; // 2^2 = 4 collisions
    static final int bucket_mask = 0x0fff; // 12 bits
    static final int sample_mask = ~bucket_mask << ignore_bits; // 18 bits
    static final int sample_shift = Integer.numberOfTrailingZeros(~bucket_mask);

    static int zero_extend(byte b) {
        return b < 0 ? 256+b : (int) b;
    }

    static int hyper_log_log(MessageDigest digest, byte key[], byte data[]) {
        encrypt(digest, key, data);
        int value = 0;
        for (int i = 0; i < 4; i++) {
            value <<= 8;
            value |= zero_extend(data[i]);
        }
        int bucket = value & bucket_mask;
        int sample = value & sample_mask;
        sample = Integer.numberOfLeadingZeros(~sample);
        return (sample << sample_shift) + bucket;
    }

    static byte[] snowflake_hll(int hll) {
        int bucket = hll & bucket_mask;
        int sample = hll >>> sample_shift;
        byte data[] = {(byte)(bucket), (byte)(bucket >> 8), (byte)(sample + 1)};
        return data;
    }

    static final byte key[] = {
          66,   73, -128,  115,  -55,  -94,   69,  -93,
         117,  109,   72,  -16,  -45,   45,   22, -124,
         -54,   -6,   -6,  -20,   82,  -27,   72,  101,
         -49,   31,   74,   52,  116, -119,   73,   92,
         -98, -124,  111,  123,   30,   10,  -28,   40,
         -85, -111,   90,  -98,  -77,  -26,   54, -114,
          21,  -83,  112,  -91,  -88,   36,   79,   85,
          -3, -104,  -36, -103,   50,  -98,  -37,  -35,
          22,   40,   40,   95,   49,  -79,    3,  -82,
         100,  -70,  -94,   80,   89,  -31,  -18,  101,
         -12,   68,   27,  -32,  -69,   88,  -14,   99,
         -70,   43,   28,    3,   13,    1,  -21,  -21,
         -42,   21,    1,  121,  -95,  -17,   75,  112,
        -128,  -10,   40,   65,  127,   -2,   57,   99,
          82,  -85,   34,   70,  -94,  -81,   -8,  -39,
         -62,  -15,  -36,  -63,   56,   50,  -98,   38,
         124,   98,   94,   55,  113,   15,   65,   16,
          12,  110,   39,   24,  -35,   62,   -3,    0,
         -77,  -91,   62, -117, -113,  100, -122,   13,
          74,  -24, -115,  -60,  -96,   30,  120,   -2,
         -82, -113,   68,  -67,   42,   38,  -68,  -85,
         -51,   91,  -40, -106,  101,  -92,  -37, -105,
          41, -119, -101,   20,   24,    7,   23,   51,
          49,  -79,    3,   98,   58,  123,   44, -114,
         -14,  -33,  -84,    0,   13,  -11,  -26,   83,
          -9,   -3,  109,  -31,  -21,  -83,  -61,  -61,
        -109,  125,  -45,   76,   49,   63,  -50,   88,
         -22,   39,   24,   76,  114,   -4,   62,  -36,
        -114,  -64, -109,  117,  -18,  -33,    0,  -82,
        -102,   59,   36,  -52, -122,  -66,   37,   80,
         -23,  -20,   30,  -24,  -67,  -14,  113,   42,
           6,    6,   -3,    1,   57,  -11,  -91,  -11,
          56,   94,   51,  125,   74,   71, -127,   13,
         114,    2,   -8, -126,  -47,  -64,  -57,   87,
         -33, -121,  -33,   74,  -96,  125,   79,  -72,
         -47, -106,  -82,  -46,   73,  -65, -127,  118,
          45,  -37,   -6, -116,   49,  -59,  -72,  108,
         101,  -38,   58, -119,   -9,  -92,  -56,  -34,
          20,   22,    6,    8,  -18,  106,  -31,   17,
          -7,   85,   46,  -93,   50,   88,   23,  -11,
        -110,    6,  -27,   49, -125,  -28,   49, -125,
        -114,  116,  120,   -5,   54,   40,  -50,  115,
         -84,   36,    2,  101, -124, -123,  -69,   52,
         -13,  126,  -26,   85,   22, -120,  -39,  -50,
         -91,   21,   96,   99,  -60,   86,   -4,  -59,
         -69,  -92,  -70,  -34,  -78,   26,   41,  106,
          -3,   86,  -61,   72,  -78,   59,  -32,  -85,
         -22,  -49,   80, -101,   -7,  -84,  -30,   54,
         -51,   75,   47,  -67,  114,   -4,  111,   48,
          25,  108,   28, -119,  -40, -121, -115, -113,
          -6,  -47,  117, -102,  -83, -114,   -7,   -9,
        -102,   42,  -12, -106, -124,   85,  -97,  112,
          -6,   37,   97,  -63,  -98,   40,  110,  -43,
         109,   88,  104,   52,  -12,  121,  -90,  -85,
         -21,  -91,   55,   27,  -15,  -40,   53,   62,
         -52,  -65, -104,   65,  -57,  -82,   37,   56,
         -28,   53, -118,  124,   39,   -1,  -27,   64,
        -128,  103,  -69,   97,   43,  -99,  109, -118,
         -77, -101,   42,  -11,  100,  -66,  -51,   16,
          -4,  -58,  -86,    4,   -9,  122,  -78,   62,
         -25,   49,   67,    7,  -57,  -26,   47,   61,
          73,  -82,   59,   76,  -44,  -28,   35,   69,
         102,  -13,    2, -117,   60,   46, -114, -123,
          55,  -34,   75,  -54,  118,   49,   44,   75
    };

    static MessageDigest getDigest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-512");
    }

    public static byte[] hll_hash_ip(String addr)
        throws NoSuchAlgorithmException, UnknownHostException
    {
        byte data[] = InetAddress.getByName(addr).getAddress();
        return snowflake_hll(hyper_log_log(getDigest(), key, data));
    }

    public static void main(String[] args)
        throws NoSuchAlgorithmException, UnknownHostException
    {
        MessageDigest digest = getDigest();
        for (String arg : args) {
            byte hll[] = hll_hash_ip(arg);
            int bucket = (zero_extend(hll[1]) << 8) | zero_extend(hll[0]);
            int sample = hll[2] - 1;
            System.out.println(arg + " => " + bucket + "," + sample + " => " + Arrays.toString(hll));
        }
    }
}
