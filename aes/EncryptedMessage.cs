using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aes
{
    public class EncryptedMessage
    {
        public byte[] MessageBytes { get; set; } = Array.Empty<byte>();
        public byte[] Key { get; set; } = Array.Empty<byte>();
        public byte[] IV { get; set; } = Array.Empty<byte>();

        public EncryptedMessage()
        {
        }

        public EncryptedMessage(byte[] messageBytes, byte[] key, byte[] iv)
        {
            MessageBytes = messageBytes;
            Key = key;
            IV = iv;
        }
    }
}
