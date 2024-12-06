public class App {
    public static void main(String[] args) throws Exception {
        ElGamal elGamal = new ElGamal();
        elGamal.ReadPrivateKeyFromFile("task/sk.txt");
        String chiffre = elGamal.ReadFromFile("task/chiffre.txt");

        System.out.println("Decrypted: " + elGamal.Decrypt(chiffre));

        // Generate new keys
        elGamal.GenerateKeys(4096);

        // Encrypt and decrypt a message
        String encrypted = elGamal.Encrypt("Test");
        System.out.println("Decrypted: " + elGamal.Decrypt(encrypted));

        // Encrypt and decrypt a message from file
        String message = elGamal.ReadFromFile("text.txt");
        elGamal.EncryptToFile("chiffre.txt", message);

        String decrypted = elGamal.DecryptFromFile("chiffre.txt");
        elGamal.WriteToFile("text-d.txt", decrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
