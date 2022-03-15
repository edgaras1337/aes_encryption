using System.Security.Cryptography;

namespace aes
{
    public class EncryptedMessage
    {
        public byte[] MessageBytes { get; set; } = Array.Empty<byte>();
        public byte[] Key { get; set; } = Array.Empty<byte>();
        public byte[] IV { get; set; } = Array.Empty<byte>();
        public CipherMode CipherMode { get; set; }

        public EncryptedMessage()
        {
        }

        public EncryptedMessage(byte[] messageBytes, byte[] key, byte[] iv, CipherMode cipherMode)
        {
            MessageBytes = messageBytes;
            Key = key;
            IV = iv;
            CipherMode = cipherMode;
        }
    }
}
