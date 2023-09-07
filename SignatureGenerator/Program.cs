using System;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Collections.Generic;

namespace SignatureGenerator
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: SignatureGenerator <directory_path> <virus_type>");
                return;
            }

            var directoryPath = args[0];
            var virusType = args[1];
            var signatures = LoadSignaturesFromFile();

            if (Directory.Exists(directoryPath))
            {
                ProcessDirectory(directoryPath, virusType, signatures);
                File.WriteAllText("signatures.json", JsonConvert.SerializeObject(signatures, Formatting.Indented));
            }
            else
            {
                Console.WriteLine("Specified directory does not exist.");
            }
        }

        private static void ProcessDirectory(string directoryPath, string virusType, Dictionary<string, Dictionary<string, List<string>>> signatures)
        {
            foreach (var file in Directory.GetFiles(directoryPath))
            {
                GenerateSignaturesForFile(file, virusType, signatures);
            }

            foreach (var subDirectory in Directory.GetDirectories(directoryPath))
            {
                ProcessDirectory(subDirectory, virusType, signatures);
            }
        }

        private static void GenerateSignaturesForFile(string filePath, string virusType, Dictionary<string, Dictionary<string, List<string>>> signatures)
        {
            using (var stream = File.OpenRead(filePath))
            {
                var data = new byte[stream.Length];
                stream.Read(data, 0, (int)stream.Length);
                var startIndex = data.Length > 2 && data[0] == 0x4D && data[1] == 0x5A ? 512 : 0;
                var sliceSize = (data.Length - startIndex) / 12;
                List<string> generatedSignatures = new List<string>();

                for (int i = 0; i < 12; i++)
                {
                    var segment = new byte[sliceSize];
                    Array.Copy(data, startIndex + (i * sliceSize), segment, 0, sliceSize);
                    generatedSignatures.Add(GenerateSignature(segment));
                }

                if (!signatures.ContainsKey(virusType))
                {
                    signatures[virusType] = new Dictionary<string, List<string>>();
                }

                var random = new Random();
                var animals = new List<string> { "Lion", "Tiger", "Bear", "Eagle", "Shark", "Jaguar", "Panda", "Elephant", "Leopard", "Rhinoceros" };
                var uniqueName = $"{animals[random.Next(animals.Count)]}!{virusType}";
                signatures[virusType][uniqueName] = generatedSignatures;
            }
        }

        private static string GenerateSignature(byte[] data)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return BitConverter.ToString(sha256.ComputeHash(data)).Replace("-", "");
            }
        }

        private static Dictionary<string, Dictionary<string, List<string>>> LoadSignaturesFromFile()
        {
            var filePath = "signatures.json";
            if (File.Exists(filePath))
            {
                var data = File.ReadAllText(filePath);
                return JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, List<string>>>>(data);
            }
            return new Dictionary<string, Dictionary<string, List<string>>>();
        }
    }
}
