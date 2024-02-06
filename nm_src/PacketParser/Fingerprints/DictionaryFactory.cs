using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace PacketParser.Fingerprints
{
    class DictionaryFactory {
        //JSON serializer is available from .NET 3.0 (not in .NET Framework)
        //https://docs.microsoft.com/en-us/dotnet/api/system.text.json.jsonserializer.serialize?view=netcore-3.0

        //{"desc":"Adium 1.5.10 (a)","ja3_hash":"93948924e733e9df15a3bb44404cd909","ja3_str":"769,255-49188-49187-49162-49161-49160-49192-49191-49172-49171-49170-49190-49189-49157-49156-49155-49194-49193-49167-49166-49165-107-103-57-51-22-61-60-53-47-10-49159-49169-49154-49164-5,0-10-11-13,23-24-25,0"}
        public static Dictionary<string, string> CreateDictionaryFromTrisulJa3Json(string jsonDictionary) {
            //Dictionary<string, string> dict = new Dictionary<string, string>();
            System.Text.RegularExpressions.Regex regex = new System.Text.RegularExpressions.Regex("\"desc\":\"(?<desc>[^\"]*)\",\"ja3_hash\":\"(?<hash>[^\"]*)\"");
            return CreateDictionaryFromLineRegex(regex, "hash", "desc", jsonDictionary);
        }

        public static Dictionary<string, string> CreateDictionaryFromLineRegex(System.Text.RegularExpressions.Regex regex, string keyName, string valueName, string filePath) {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            foreach (string line in System.IO.File.ReadLines(filePath)) {
                System.Text.RegularExpressions.Match match = regex.Match(line);
                if (match.Success) {
                    string key = match.Groups[keyName].Value;
                    if (!dict.ContainsKey(key))
                        dict.Add(key, match.Groups[valueName].Value);
                }
            }
            return dict;
        }

        public static Dictionary<string, string> CreateDictionaryFromCsv(string csvFile, int keyColumn, int valueColumn, bool skipFirstLine = false) {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            int maxColIndex = Math.Max(keyColumn, valueColumn);
            int lineCount = 0;
            foreach (string line in System.IO.File.ReadLines(csvFile)) {
                if (lineCount > 0 || !skipFirstLine) {
                    if (!string.IsNullOrWhiteSpace(line) && !line.StartsWith("#")) {
                        string[] cols = line.Split(',');
                        if (cols.Length > maxColIndex) {
                            string key = cols[keyColumn].Trim();
                            if (!dict.ContainsKey(key))
                                dict.Add(key, cols[valueColumn].Trim());
                        }
                    }
                }
                lineCount++;
            }
            return dict;
        }
    }
}
