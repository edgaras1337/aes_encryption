using aes;
using System.Security.Cryptography;
using System.Text;

// set the default values
char opt = ' ';
string filePath = "";
EncryptedMessage? encryptedFile = null;
CipherMode cipherMode = CipherMode.CBC; // random default mode, it will be changed later

while (opt != '0')
{
    Console.WriteLine("\n----------------------");
    Console.WriteLine("1 - encrypt a message with generated security key and display");
    Console.WriteLine("2 - encrypt a message with custom security key and display");
    Console.WriteLine("3 - read encrypted message from a file and decrypt");
    Console.WriteLine("0 - exit");
    Console.WriteLine("----------------------");
    Console.Write("\nYour input: ");
    opt = Console.ReadKey(true).KeyChar;
    Console.WriteLine(opt);

    if (opt == '1' || opt == '2')
    {
        EncryptedMessage encrypted;
        string messageToEncrypt = "";

        // choose the cipher mode
        Console.WriteLine("\n1 - ECB");
        Console.WriteLine("2 - CBC");
        Console.WriteLine("3 - CFB");

        CipherMode? tempMode = null;
        while (tempMode is null)
        {
            Console.Write("\nChoose a cypher mode: ");
            char modeOpt = Console.ReadKey(true).KeyChar;
            Console.Write(modeOpt);

            switch (modeOpt)
            {
                case '1':
                    tempMode = CipherMode.ECB;
                    break;
                case '2':
                    tempMode = CipherMode.CBC;
                    break;
                case '3':
                    tempMode = CipherMode.CFB;
                    break;
                default:
                    Console.WriteLine("\n\nWrong input!");
                    break;
            }
        }
        cipherMode = (CipherMode)tempMode;

        // enter message to encrypt
        while (messageToEncrypt == "")
        {
            Console.Write("\n\nEnter your message: ");
            messageToEncrypt = Console.ReadLine()!;
        }

        // insert custom key
        if (opt == '2')
        {
            try
            {
                string keyString = "";
                while (keyString == "")
                {
                    Console.Write("Enter the Key: ");
                    keyString = Console.ReadLine()!;
                }

                // check the length of key and add padding accordingly (16, 24 or 32 bits)
                if (keyString.Length < 16)
                {
                    keyString = keyString.PadLeft(16, '*');
                }
                else if (keyString.Length < 24)
                {
                    keyString = keyString.PadLeft(24, '*');
                }
                else if (keyString.Length < 32)
                {
                    keyString = keyString.PadLeft(32, '*');
                }
                else if (keyString.Length > 32)
                {
                    throw new Exception("\nKey size cant be longer than 32 bits!");
                }
                byte[] keyBytes = Encoding.UTF8.GetBytes(keyString);

                // change key size based on key length
                int? keySize = null;
                if (keyBytes.Length > 16)
                {
                    keySize = 192;
                }
                else if (keyBytes.Length > 32)
                {
                    keySize = 256;
                }

                // encrypt the data with custom key
                encrypted = AesService.EncryptToBytes(messageToEncrypt, keyBytes, keySize, cipherMode);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                continue;
            }
        }
        else
        {
            try
            {
                // encrypt data with auto generated key
                encrypted = AesService.EncryptToBytes(messageToEncrypt, null, null, cipherMode);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n{ex.Message}");
                continue;
            }
        }

        Console.WriteLine($"\nEncrypted message: {Convert.ToBase64String(encrypted.MessageBytes)}");

        Console.Write("\nDo you want to save the encrypted message into a file? (Y/N) ");
        char yn = ' ';
        while (yn != 'y' && yn != 'n')
        {
            yn = char.ToLower(Console.ReadKey(true).KeyChar);
            Console.WriteLine(yn);

            if (yn == 'y')
            {
                try
                {
                    // get the solution directory
                    string workingDir = Environment.CurrentDirectory;
                    string solutionDir = Directory.GetParent(workingDir)!.Parent!.Parent!.FullName;

                    // create a file path inside the solution directory
                    filePath = Path.Combine(solutionDir, "encoded.txt");

                    // write the message converted to base64 string
                    using (var outputFile = new StreamWriter(filePath))
                    {
                        outputFile.WriteLine(Convert.ToBase64String(encrypted.MessageBytes));
                    }

                    // create object with the data of encrypted message which is saved in file
                    encryptedFile = new EncryptedMessage(
                        encrypted.MessageBytes, encrypted.Key, encrypted.IV, cipherMode);

                    Console.WriteLine("\nMessage saved successfully!");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"\n{ex.Message}");
                    continue;
                }
            }
            else if (yn != 'n')
            {
                Console.WriteLine("Wrong input!");
            }
        }

        try
        {
            Console.Write("\nDo you want to decrypt the same message? (Y/N) ");
            yn = ' ';
            while (yn != 'y' && yn != 'n')
            {
                yn = char.ToLower(Console.ReadKey(true).KeyChar);
                Console.WriteLine(yn);

                if (yn == 'y')
                {
                    // decrypt message
                    string roundTrip = AesService.DecryptFromBytes(
                        encrypted.MessageBytes, encrypted.Key, encrypted.IV, cipherMode);

                    Console.WriteLine($"\nDecrypted message: {roundTrip}");
                }
                else if (yn != 'n')
                {
                    Console.WriteLine("Wrong input!");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n{ex.Message}");
        }
    }
    else if (opt == '3')
    {
        try
        {
            // check if file or object with encryption params exists
            if (encryptedFile is null || !File.Exists(filePath))
            {
                Console.WriteLine("\nNo data was found!");
                continue;
            }

            // read encoded message to string from file
            string messageString;
            using (var reader = new StreamReader(filePath))
            {
                messageString = reader.ReadToEnd();
            }
            // convert string to bytes
            byte[] messageBytes = Convert.FromBase64String(messageString);

            // decrypt bytes into a string
            // passing: converted message bytes, key and IV stored in an object
            string roundTrip = AesService.DecryptFromBytes(
                messageBytes, encryptedFile.Key, encryptedFile.IV, cipherMode);

            Console.WriteLine($"\nEncrypted message read from file: {messageString}");
            Console.WriteLine($"Decrypted message from file: {roundTrip}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\n{ex.Message}");
        }
    }
    else if (opt == '0')
    {
        break;
    }
    else
    {
        Console.WriteLine("\nWrong input!");
    }
}
// delete file with encrypted data on close
if (File.Exists(filePath))
{
    File.Delete(filePath);
}
