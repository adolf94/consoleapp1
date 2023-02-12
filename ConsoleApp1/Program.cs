

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            const string password = "secret-key";
            string encrypted = Encrypt(password, "sensitive information");
            Console.WriteLine("Encrypted Data: " + encrypted);

            string decrypted = Decrypt(password, encrypted);
            Console.WriteLine("Decrypted Data: " + decrypted);
            Console.ReadLine();
        }

        private static string Encrypt(string password, string data)
        {
            byte[] iv = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv);
            }

            byte[] key = KeyDerivation.Pbkdf2(password, iv, KeyDerivationPrf.HMACSHA1, 1000, 16);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(data);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                    Console.WriteLine(Convert.ToBase64String(encryptedBytes));
                    Console.WriteLine(Convert.ToBase64String(iv));
                    //string encryptedHex = BitConverter.ToString(iv).Replace("-", string.Empty) + BitConverter.ToString(encryptedBytes).Replace("-", string.Empty);
                    return Convert.ToBase64String(iv) + Convert.ToBase64String(encryptedBytes);
                    //return encryptedHex;
                }
            }
        }

        private static string Decrypt(string password, string encryptedHex)
        {
            //Array.Copy(StringToByteArray(encryptedHex.Substring(0, 32)), iv, 16);
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(encryptedHex.Substring(16));

            byte[] iv = bytes.Take(16).ToArray();
            byte[] encryptedBytes = bytes.Skip(16).ToArray();
            byte[] key = KeyDerivation.Pbkdf2(password, iv, KeyDerivationPrf.HMACSHA1, 1000, 16);

            Console.WriteLine(Convert.ToBase64String(encryptedBytes));
            Console.WriteLine(Convert.ToBase64String(iv));
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Padding = PaddingMode.PKCS7;
                aes.Mode = CipherMode.CBC;

                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }
        private static byte[] StringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }
            return bytes;
        }
    }
}