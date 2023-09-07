using System;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace SignatureChecker
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: SignatureChecker <target_file_path>");
                return;
            }

            var targetPath = args[0];
            var signatures = LoadSignaturesFromFile();

            if (Path.GetExtension(targetPath) == ".zip")
            {
                using (var zip = ZipFile.OpenRead(targetPath))
                {
                    foreach (var entry in zip.Entries)
                    {
                        using (var stream = new MemoryStream())
                        {
                            entry.Open().CopyTo(stream);
                            CheckStreamForSignatures(stream.ToArray(), signatures, entry.Name);
                        }
                    }
                }
            }
            else
            {
                var data = File.ReadAllBytes(targetPath);
                CheckStreamForSignatures(data, signatures, Path.GetFileName(targetPath));
            }
        }

        private static void CheckStreamForSignatures(byte[] data, Dictionary<string, Dictionary<string, List<string>>> signatures, string filename)
        {
            var startIndex = data.Length > 2 && data[0] == 0x4D && data[1] == 0x5A ? 512 : 0;
            var sliceSize = (data.Length - startIndex) / 12;
            var detectedSignatures = new Dictionary<string, List<string>>();

            for (int i = 0; i < 12; i++)
            {
                var segment = new byte[sliceSize];
                Array.Copy(data, startIndex + (i * sliceSize), segment, 0, sliceSize);
                var signature = GenerateSignature(segment);

                foreach (var virusFamily in signatures)
                {
                    foreach (var uniqueName in virusFamily.Value)
                    {
                        if (uniqueName.Value.Contains(signature))
                        {
                            if (!detectedSignatures.ContainsKey(virusFamily.Key))
                            {
                                detectedSignatures[virusFamily.Key] = new List<string>();
                            }
                            detectedSignatures[virusFamily.Key].Add(uniqueName.Key);
                        }
                    }
                }
            }

            DisplayDetectionSummary(filename, detectedSignatures);
        }

        private static void DisplayDetectionSummary(string filename, Dictionary<string, List<string>> detectedSignatures)
        {
            var output = new StringBuilder();
            output.AppendLine($"Analysis for {filename}:");
            output.AppendLine(new string('-', 50));

            if (detectedSignatures.Any())
            {
                output.AppendLine("Potential malware detected:");
                foreach (var detection in detectedSignatures)
                {
                    output.AppendLine($"\nType: {detection.Key}");
                    foreach (var uniqueName in detection.Value.Distinct())
                    {
                        output.AppendLine($" - Signature: {uniqueName}");
                    }
                }
                output.AppendLine($"\nTotal Types Detected: {detectedSignatures.Count}");
                output.AppendLine($"Total Signatures Detected: {detectedSignatures.Sum(d => d.Value.Distinct().Count())}");
            }
            else
            {
                output.AppendLine("No malware signatures detected.");
            }

            Console.WriteLine(output.ToString());
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
