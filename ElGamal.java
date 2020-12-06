import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.Random;

/*
 *  ElGamal signatur encryption program.
 *  Max size for the signature is 256 bytes (2048 bits)
 */
public class ElGamal {

    private static final Random RND = new Random();
    private static final int BITLENGTH = 512 * 2 * 2;
    private static final int CERTAINTY = 1000;

    private static BigInteger publicGenerator;
    private static BigInteger publicPrime;
    private static BigInteger plaintext;

    public static void main(String[] args) {
        
        //generatePublicPrimeAndGenerator();
        
        plaintext = readBigIntegerFromFile("sha256sum");
        publicGenerator = readBigIntegerFromFile("generator");
        publicPrime = readBigIntegerFromFile("prime");
        encrypt();

    }

    /*
    *   These functions is not part of the actual encryption software,
    *   only used to generate prime and generator.
    */
    static void generatePublicPrimeAndGenerator() {
        setCyclicGroup();
        setGenerator(publicPrime, publicPrime.add(new BigInteger("1").negate()));
        writeBigIntegerToFile(publicGenerator, "generator");
        writeBigIntegerToFile(publicPrime, "prime");
    }

    /*  
    *   From section 4.86 Algo 
    *   p is created with 2q + 1 to later easily find a generator
    */
    static void setCyclicGroup() {
        BigInteger q = new BigInteger(BITLENGTH, CERTAINTY, RND);
        BigInteger p;
        while (true) {
            p = new BigInteger("2").multiply(q).add(new BigInteger("1"));
            if (p.isProbablePrime(CERTAINTY)) {
                break;
            } else {
                System.out.println("p not prime");
            }
            q = new BigInteger(BITLENGTH, CERTAINTY, RND);
        }
        publicPrime = p;
    }

    /* 
    *   From section 4.80 Algo in Cryptography Handbook
    *   n = p - 1
    */
    static void setGenerator(BigInteger cyclicGroup, BigInteger n) {
        System.out.println("Trying to find generator-----");
        BigInteger primeFactor = n.divide(new BigInteger("2"));
        while (true) {
            int randomBitLength = RND.nextInt(BITLENGTH - 1 + 1);
            BigInteger randomElementInGroup = new BigInteger(randomBitLength, RND);
            if (randomElementInGroup.compareTo(cyclicGroup) < 0) {
                BigInteger b = randomElementInGroup.modPow(n, primeFactor);

                //If b != 1, use randomElementInGroup as generator
                if (!(b.compareTo(new BigInteger("1")) == 0)) {
                    publicGenerator = randomElementInGroup;
                    System.out.println("g: " + publicGenerator);
                    System.out.println("p: " + publicPrime);
                    break;
                }
            }
        }
    }

    static void encrypt() {
        //Random BigInteger with BITLENGTH between 1 and BITLENGTH
        BigInteger privateAlice = new BigInteger(RND.nextInt(BITLENGTH - 1 + 1), RND);

        //Check if privateAlice is less than publicPrime - 1
        while (true) {
            if (privateAlice.compareTo(publicPrime.add(new BigInteger("1").negate())) < 0) {
                break;
            }
            privateAlice = new BigInteger(RND.nextInt(BITLENGTH - 1 + 1), RND);
        }

        BigInteger publicAlice = publicGenerator.modPow(privateAlice, publicPrime);

        //Random BigInteger with BITLENGTH between 1 and BITLENGTH
        BigInteger privateBob = new BigInteger(RND.nextInt(BITLENGTH - 1 + 1), RND);
        //Check if privateBob is less than publicPrime - 1
        while (true) {
            if (privateBob.compareTo(publicPrime.add(new BigInteger("1").negate())) < 0) {
                break;
            }
            privateBob = new BigInteger(RND.nextInt(BITLENGTH - 1 + 1), RND);
        }

        BigInteger c1 = publicGenerator.modPow(privateBob, publicPrime);

        BigInteger c2 = fastModExpExtended(plaintext,
                publicAlice, privateBob, publicPrime);

        BigInteger t = publicPrime.add(privateAlice.negate());
        t = t.add(new BigInteger("1").negate());
        BigInteger ypla = c1.modPow(t, publicPrime);
        BigInteger decryptedMessage = ypla.multiply(c2).mod(publicPrime);

        //Since BITLENGTH is static, I assume this is known for all parts, and not part of the public info.
        System.out.println("Plaintext: " + BigIntegerToRealString(plaintext));
        System.out.println("Public prime: " + publicPrime);
        System.out.println("Public generator: " + publicGenerator);
        System.out.println("Public alice: " + publicAlice);
        System.out.println("Ciphertext1: " + c1);
        System.out.println("Ciphertext2: " + c2);
        System.out.println("Decrypted plaintext: " + BigIntegerToRealString(decryptedMessage));
        System.out.println("'Plaintext' and 'Decrypted plaintext' is the same message: " + (plaintext.compareTo(decryptedMessage) == 0));

        writeBigIntegerToFile(decryptedMessage, "decryptedFile");
    }

    /*
    *   Function to convert BigInteger to bytes first then a readable string
    */
    static String BigIntegerToRealString(BigInteger i){
        String s = "";
        byte[] arr = i.toByteArray();
        for (byte b : arr) {
            char c = (char)b;
            s = s + c;
        }
        return s;
    }
    

    static void writeBigIntegerToFile(BigInteger message, String filename) {
        File f = new File(filename);
        byte[] arr = message.toByteArray();
        try {
            Files.write(f.toPath(), arr);
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    static BigInteger readBigIntegerFromFile(String filename) {
        File f = new File(filename);
        BigInteger output;
        try {
            byte[] data = Files.readAllBytes(f.toPath());
            output = new BigInteger(data);
            return output;
        } catch (IOException e) {
            System.out.println(e);
            return null;
        }
    }

    /*
    *   Function copied from page 268 in Discrete mathematics book.
    *   With 'x = a.multiply(x).mod(mod)' as a added line
    */
    static private BigInteger fastModExpExtended(BigInteger a, BigInteger b,
            BigInteger exp, BigInteger mod) {
        String exponentString = exp.toString(2);
        BigInteger x = new BigInteger("1");
        BigInteger power = b.mod(mod);
        for (int i = exponentString.length() - 1; i >= 0; i--) {
            char bit = exponentString.charAt(i);
            if (bit == '1') {
                BigInteger t1 = x.multiply(power);
                x = x.multiply(power).mod(mod);
            }
            power = power.multiply(power).mod(mod);
        }
        //Extra line
        x = a.multiply(x).mod(mod);
        return x;
    }

    
}
