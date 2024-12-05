import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

public class ElGamal {
	private BigInteger n, g, publicKey, privateKey; // Public and private keys
	private SecureRandom random = new SecureRandom();

	public ElGamal() {
		String nHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
				+ "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
				+ "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
				+ "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
				+ "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
				+ "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
				+ "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
				+ "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
				+ "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
				+ "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
				+ "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

		// Convert the hexadecimal number into a BigInteger
		n = new BigInteger(nHex, 16);
		g = BigInteger.TWO; // Generator g = 2
	}

	public void ReadPrivateKeyFromFile(String filePath) throws IOException {
		privateKey = new BigInteger(ReadFromFile(filePath).trim());
	}

	// Initialize with a given public key
	public void ReadPublicKeyFromFile(String filePath) throws IOException {
		publicKey = new BigInteger(ReadFromFile(filePath).trim());
	}

	public void GenerateKeys(int bitLength) throws IOException {
		// Generate a random private key x in 1 ... n-1
		privateKey = new BigInteger(bitLength - 1, random).mod(n);
		publicKey = g.modPow(privateKey, n); // Public key h = g^x mod n

		WriteToFile("pk.txt", publicKey.toString());
		WriteToFile("sk.txt", privateKey.toString());
	}

	public String Encrypt(String message) {
		StringBuilder sb = new StringBuilder();
		for (char c : message.toCharArray()) {
			BigInteger asciiValue = BigInteger.valueOf(c);
			// Get random a in 1 ... n-1
			BigInteger a = new BigInteger(n.bitLength() - 1, random).mod(n);
			// Calculate first part g^a mod n
			BigInteger y1 = g.modPow(a, n);
			// Calculate second part pk^a * m mod n
			BigInteger s = publicKey.modPow(a, n);
			BigInteger y2 = asciiValue.multiply(s).mod(n);
			sb.append("(" + y1 + "," + y2 + ");");
		}
		return sb.toString();
	}

	// Decrypt a single ciphertext pair
	public String Decrypt(String message) {
		String[] pairs = message.split(";");
		StringBuilder sb = new StringBuilder();
		for (String pair : pairs) {
			if (pair.trim().isEmpty())
				continue;
			String[] components = pair.replace("(", "").replace(")", "").split(",");
			BigInteger y1 = new BigInteger(components[0]);
			BigInteger y2 = new BigInteger(components[1]);

			// Calculate y1^sk mod n
			BigInteger ab = y1.modPow(privateKey, n);
			BigInteger abInverse = ab.modInverse(n);
			BigInteger decryptedAscii = y2.multiply(abInverse).mod(n);
			sb.append((char) decryptedAscii.intValue());
		}
		return sb.toString();
	}

	public String DecryptFromFile(String filePath) throws IOException {
		return Decrypt(ReadFromFile(filePath));
	}

	public void EncryptToFile(String filePath, String message) throws IOException {
		WriteToFile(filePath, Encrypt(message));
	}

	public void WriteToFile(String filename, String content) {
		try {
			Files.write(Paths.get(filename), content.getBytes());
		} catch (Exception e) {
			System.out.println("Error writing file");
			e.printStackTrace();
		}
	}

	public String ReadFromFile(String filename) {
		try {
			return new String(Files.readAllBytes(Paths.get(filename)), StandardCharsets.UTF_8);
		} catch (Exception e) {
			System.out.println("Error reading file");
			e.printStackTrace();
			return "";
		}
	}
}
