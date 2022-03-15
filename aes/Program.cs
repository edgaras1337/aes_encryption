using aes;
using System.Security.Cryptography;
using System.Text;

char opt = ' ';

string filePath = "";
EncryptedMessage? encryptedFile = null;// = new EncryptedMessage();
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

        while (messageToEncrypt == "")
        {
            Console.Write("Enter your message: ");
            messageToEncrypt = Console.ReadLine()!;
        }

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

                int? keySize = null;
                if (keyBytes.Length > 16)
                {
                    keySize = 192;
                }
                else if (keyBytes.Length > 32)
                {
                    keySize = 256;
                }

                encrypted = AesService.EncryptToBytes(messageToEncrypt, keyBytes, keySize);

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);

                continue;
            }
        }
        else
        {
            encrypted = AesService.EncryptToBytes(messageToEncrypt, null, null);
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
                string workingDir = Environment.CurrentDirectory;
                string projDir = Directory.GetParent(workingDir)!.Parent!.Parent!.FullName;
                filePath = Path.Combine(projDir, "encoded.txt");

                using (var outputFile = new StreamWriter(filePath))
                {
                    outputFile.WriteLine(Convert.ToBase64String(encrypted.MessageBytes));
                }

                encryptedFile = new EncryptedMessage(encrypted.MessageBytes, encrypted.Key, encrypted.IV);


                Console.WriteLine("\nMessage saved successfully!");
            }
            else if (yn != 'n')
            {
                Console.WriteLine("Wrong input!");
            }
        }

        Console.Write("\nDo you want to decrypt the same message? (Y/N) ");
        yn = ' ';
        while (yn != 'y' && yn != 'n')
        {
            yn = char.ToLower(Console.ReadKey(true).KeyChar);
            Console.WriteLine(yn);

            if (yn == 'y')
            {
                string roundTrip = AesService.DecryptFromBytes(encrypted.MessageBytes, encrypted.Key, encrypted.IV);
                Console.WriteLine($"\nDecrypted message: {roundTrip}");
            }
            else if (yn != 'n')
            {
                Console.WriteLine("Wrong input!");
            }
        }
    }
    else if (opt == '3')
    {
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
            messageBytes, encryptedFile.Key, encryptedFile.IV);

        Console.WriteLine($"\nEncrypted message read from file: {messageString}");
        Console.WriteLine($"Decrypted message from file: {roundTrip}");
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
if (File.Exists(filePath))
{
    File.Delete(filePath);
}
