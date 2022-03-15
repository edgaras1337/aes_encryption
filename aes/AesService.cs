using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace aes
{
    public class AesService
    {
        public static EncryptedMessage EncryptToBytes(string plainText, byte[]? key, int? keySize)
        {
            byte[] encrypted;
            byte[] iv;
            using (Aes aesAlg = Aes.Create())
            {
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
                iv = aesAlg.IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using var msEncrypt = new MemoryStream();
                using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    //Write all data to the stream.
                    swEncrypt.Write(plainText);
                }
                encrypted = msEncrypt.ToArray();
            }

            // Return the encrypted bytes from the memory stream.
            return new EncryptedMessage(encrypted, key, iv);
        }

        public static string DecryptFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            string? plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using var msDecrypt = new MemoryStream(cipherText);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);

                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }
    }
}
