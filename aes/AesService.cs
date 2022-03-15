using System.Security.Cryptography;

namespace aes
{
    public class AesService
    {
        public static EncryptedMessage EncryptToBytes(
            string plainText, byte[]? key, int? keySize, CipherMode cipherMode)
        {
            byte[] encrypted;
            byte[] iv;
            using (Aes aesAlg = Aes.Create())
            {
                // set cipher parameters (key, key size, cipher mode)
                if (key != null && keySize != null)
                {
                    if (keySize != null)
                    {
                        aesAlg.KeySize = (int)keySize;
                    }

                    aesAlg.Key = key;
                }
                else
                {
                    key = aesAlg.Key;
                }
                aesAlg.Mode = cipherMode;

                // store aes IV, to later use inside EncryptedMessage obj
                iv = aesAlg.IV;

                // create encryptor for CryptoStream
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // create the streams used for encryption
                using var msEncrypt = new MemoryStream();
                using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
                encrypted = msEncrypt.ToArray();
            }

            return new EncryptedMessage(encrypted, key, iv, cipherMode);
        }

        public static string DecryptFromBytes(byte[] cipherText, byte[] key, byte[] iv, CipherMode mode)
        {
            string? plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                // set cipher parameters
                aesAlg.Key = key;
                aesAlg.IV = iv;
                aesAlg.Mode = mode;

                // create decryptor for CryptoStream
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // create streams used for decryption
                using var msDecrypt = new MemoryStream(cipherText);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);

                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }
    }
}
