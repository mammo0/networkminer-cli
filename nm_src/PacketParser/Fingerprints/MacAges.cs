using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Collections;

namespace PacketParser.Fingerprints {

    /// <summary>
    /// Based on HD Moore's MAC Address Age Tracking, which is inspired by DeepMAC
    /// https://github.com/hdm/mac-ages
    /// https://twitter.com/hdmoore/status/1046563911972130819
    /// </summary>
    public class MacAges {

        /**
         * 000000000000/24,2000-09-08,deepmac.org
         * 000001000000/24,2000-09-08,deepmac.org
         * 000002000000/24,2000-09-08,deepmac.org
         * 000003000000/24,2000-09-08,deepmac.org
         * ...
         * 
         * egrep -o '/[0-9]*' < mac-ages.csv| sort | uniq -c
         * 36 /16
         * 25774 /24
         * 2 /25
         * 2276 /28
         * 6 /32
         * 7462 /36
         * 8 /40
         * 2 /44
         * 2 /45
         **/

        private static MacAges singletonInstance = null;
        private static readonly object macCollectionLock = new object();

        public static MacAges GetMacAges(string applicationExecutablePath) {
            lock (macCollectionLock) {
                if (singletonInstance == null) {
                    singletonInstance = new MacAges(Path.GetDirectoryName(applicationExecutablePath) + System.IO.Path.DirectorySeparatorChar + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "mac-ages.csv");
                }
            }
            return singletonInstance;
        }

        private readonly Dictionary<UInt64, Tuple<string, string>> macRangeAge = new Dictionary<ulong, Tuple<string, string>>();
        private System.Collections.BitArray maskIndicator = new BitArray(49, false);

        public MacAges(string macAgesCsvFilePath) {

            using (System.IO.FileStream fileStream = new FileStream(macAgesCsvFilePath, FileMode.Open, FileAccess.Read)) {
                using (StreamReader reader = new StreamReader(fileStream)) {
                    char[] separators = { ',', '/' };
                    while (!reader.EndOfStream) {
                        string line = reader.ReadLine();
                        string[] s = line.Split(separators);
                        if (Byte.TryParse(s[1], out byte mask)) {

                            UInt64 macNumber = this.GetMacNumber(s[0], mask, out bool bitsShiftedOut);
                            if (!bitsShiftedOut && !macRangeAge.ContainsKey(macNumber)) {
                                macRangeAge.Add(macNumber, new Tuple<string, string>(s[2], s[3]));
                                maskIndicator[mask] = true;
                            }
                        }

                    }
                }

            }

        }



        public bool TryGetDateAndSource(string macAddress, out DateTime date, out string source) {
            for (byte mask = 48; mask > 0; mask--) {
                if (this.maskIndicator[mask]) {
                    UInt64 macNumber = this.GetMacNumber(macAddress, mask, out bool bitsShiftedOut);
                    if (this.macRangeAge.ContainsKey(macNumber)) {
                        date = DateTime.Parse(this.macRangeAge[macNumber].Item1);
                        source = this.macRangeAge[macNumber].Item2;
                        return true;
                    }
                }
            }
            date = DateTime.MinValue;
            source = null;
            return false;
        }

        private UInt64 GetMacNumber(string macAddress, byte mask, out bool bitsShiftedOut) {
            if (UInt64.TryParse(macAddress, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out ulong macNumber)) {
                ulong macNumberMasked = macNumber >> (48 - mask);//shift down so that we only have the significant part
                //here's a workaround for https://github.com/hdm/mac-ages/issues/2
                bitsShiftedOut = (macNumber != macNumberMasked << (48 - mask));
                UInt64 mask64 = mask;
                mask64 <<= 56;
                macNumberMasked |= mask64;//xor with mask
                return macNumberMasked;
            }
            else
                throw new FormatException("Invalid macAddress format, should be '00e02b000001'");//https://github.com/hdm/mac-ages/issues/7 TODO: Clean CSV file manually
        }
        
    }
}
