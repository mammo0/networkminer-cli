//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace PacketParser.Fingerprints {
    public class MacCollection {
        private static MacCollection singletonInstance=null;
        private static object macCollectionLock = new object();
        private static readonly char[] WHITESPACE = { ' ', '\t' };

        public static MacCollection GetMacCollection(string applicationExecutablePath) {
            lock (macCollectionLock) {
                if (singletonInstance == null) {
                    //http://standards.ieee.org/develop/regauth/oui/oui.txt

                    //singletonInstance = new MacCollection(Path.GetDirectoryName(applicationExecutablePath) + "\\Fingerprints\\oui.txt", MacFingerprintFileFormat.Nmap);
                    //singletonInstance=new MacCollection(Path.GetDirectoryName(applicationExecutablePath)+"\\"+"oui.txt", MacFingerprintFileFormat.Nmap);
                    //singletonInstance = new MacCollection(Path.GetDirectoryName(applicationExecutablePath) + System.IO.Path.DirectorySeparatorChar + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "oui.txt", MacFingerprintFileFormat.IEEE_OUI);
                    //singletonInstance = new MacCollection((Path.GetDirectoryName(applicationExecutablePath) + System.IO.Path.DirectorySeparatorChar + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "oui.txt", MacFingerprintFileFormat.IEEE_OUI));
                    string fingerprintPath = Path.GetDirectoryName(applicationExecutablePath) + System.IO.Path.DirectorySeparatorChar + "Fingerprints" + System.IO.Path.DirectorySeparatorChar;
                    (string, MacFingerprintFileFormat)[] databases = {
                        (fingerprintPath + "oui.txt", MacFingerprintFileFormat.IEEE_OUI),
                        (fingerprintPath + "oui36.csv", MacFingerprintFileFormat.IEEE_OUI36)
                    };
                    
                    singletonInstance = new MacCollection(databases);
                }
            }
            return singletonInstance;
        }

        private Dictionary<long, string> mac48Dictionary;//full MAC addresses
        private Dictionary<long, string> mac36Dictinoary;//oui36
        private Dictionary<long, string> mac24Dictionary;//oui/oui24

        //private System.Collections.Generic.Dictionary<string, string> macPrefixDictionary; //Format 00:11:22
        //private System.Collections.Generic.Dictionary<string, string> macFullDictionary;//Format 00:11:22:33:44:55
        public enum MacFingerprintFileFormat { Ettercap, Nmap, IEEE_OUI, IEEE_OUI36 }


        

        

        /// <summary>
        /// Reads a fingerprint file wit NIC MAC addresses. The file shall be formatted according to Ettercap
        /// </summary>
        /// <param name="macFingerprintFilename">for example "etter.finger.mac"</param>
        //private MacCollection(string macFingerprintFilename, MacFingerprintFileFormat format) {
        private MacCollection(params (string macFingerprintFilename, MacFingerprintFileFormat format)[] sources) {
            //this.macPrefixDictionary = new Dictionary<string, string>();
            //this.macFullDictionary = new Dictionary<string, string>();
            //this.macFullDictionary.Add("FF:FF:FF:FF:FF:FF", "Broadcast");

            this.mac48Dictionary = new Dictionary<long, string> {
                { 0xffffffffffff, "IEEE Broadcast" }
            };
            this.mac36Dictinoary = new Dictionary<long, string>();
            for(long i = 0; i < 0x800; i++) {
                //Start 36-bit MAC = 01:00:5E:00:0x:xx
                //Last multicast 36-bit MAC = 01:00:5E:7F:Fx:xx
                mac36Dictinoary.Add(0x01005e000 + i, "IEEE Multicast");
            }
            this.mac24Dictionary = new Dictionary<long, string>();

            foreach ((string macFingerprintFilename, MacFingerprintFileFormat format) in sources) {
                if (format == MacFingerprintFileFormat.IEEE_OUI || format == MacFingerprintFileFormat.Ettercap || format == MacFingerprintFileFormat.Nmap) {
                    using (System.IO.FileStream fileStream = new FileStream(macFingerprintFilename, FileMode.Open, FileAccess.Read)) {
                        using (StreamReader reader = new StreamReader(fileStream)) {
                            while (!reader.EndOfStream) {
                                string line = reader.ReadLine();
                                //see if it is an empty or commented line
                                if (line.Length > 0 && line[0] != '#') {
                                    string macKey = null;
                                    string vendor = null;
                                    if (format == MacFingerprintFileFormat.Ettercap && line.Length > 10) {
                                        macKey = line.Substring(0, 8);//for example 00:00:01
                                        vendor = line.Substring(10);
                                    }
                                    else if (format == MacFingerprintFileFormat.Nmap && line.Length > 7) {
                                        macKey = line.Substring(0, 2) + ":" + line.Substring(2, 2) + ":" + line.Substring(4, 2);
                                        vendor = line.Substring(7);
                                    }
                                    else if (format == MacFingerprintFileFormat.IEEE_OUI && line.Length > 15 && line.Contains("(hex)") && line.TrimStart(WHITESPACE)[2] == '-') {
                                        line = line.TrimStart(WHITESPACE);
                                        macKey = line.Substring(0, 8).Replace('-', ':');
                                        vendor = line.Substring(line.LastIndexOf('\t') + 1);
                                    }
                                    if (!string.IsNullOrEmpty(macKey) && !string.IsNullOrEmpty(vendor)) {
                                        //if(!this.macPrefixDictionary.ContainsKey(macKey))
                                        //    this.macPrefixDictionary.Add(macKey, vendor);
                                        if (long.TryParse(macKey.Replace(":", String.Empty).Trim(), System.Globalization.NumberStyles.HexNumber, null, out long m))
                                            if(!this.mac24Dictionary.ContainsKey(m))
                                                this.mac24Dictionary.Add(m, vendor);
                                    }
                                }
                            }
                        }
                    }
                }
                else if(format == MacFingerprintFileFormat.IEEE_OUI36) {
                    /**
                     * Registry,Assignment,Organization Name,Organization Address
                     * MA-S,70B3D5F2F,TELEPLATFORMS,"Polbina st., 3/1 Moscow  RU 109388 "
                     * MA-S,70B3D5719,2M Technology,802 Greenview Drive  Grand Prairie TX US 75050 
                    */
                    Dictionary<string, string> macDict = Fingerprints.DictionaryFactory.CreateDictionaryFromCsv(macFingerprintFilename, 1, 2, true);
                    foreach(KeyValuePair<string, string> kvp in macDict) {
                        if (long.TryParse(kvp.Key.Trim(), System.Globalization.NumberStyles.HexNumber, null, out long m))
                            if (!this.mac36Dictinoary.ContainsKey(m)) {
                                string orgName = kvp.Value.Trim('"', ' ', '\t');
                                if(orgName.Length > 0)
                                    this.mac36Dictinoary.Add(m, orgName);
                            }
                    }
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="macAddress">shall be in hex format. For example "00:F3:A1:01:23:45"</param>
        /// <returns></returns>
        public string GetMacVendor(string macAddress) {
            string macVendor;
            if (this.TryGetMacVendor(macAddress, out macVendor))
                return macVendor;
            else
                return "Unknown";
        }

        public bool TryGetMacVendor(System.Net.NetworkInformation.PhysicalAddress macAddress, out string macVendor) {
            if(macAddress == null) {
                macVendor = null;
                return false;
            }
            else
                return this.TryGetMacVendor(macAddress.GetAddressBytes(), out macVendor);
        }
        public bool TryGetMacVendor(byte[] macAddress, out string macVendor) {
            StringBuilder macWithColons = new StringBuilder();
            foreach(byte b in macAddress) {
                macWithColons.Append(b.ToString("X2"));
                macWithColons.Append(":");
            }
            if(macWithColons.Length>0)
                macWithColons.Remove(macWithColons.Length-1, 1);
            return this.TryGetMacVendor(macWithColons.ToString(), out macVendor);
        }


        public bool TryGetMacVendor(string macAddress, out string macVendor) {
            if (long.TryParse(macAddress.Replace(":", string.Empty), System.Globalization.NumberStyles.HexNumber, null, out long mac48)) {
                if (mac48 >= 0 && mac48 < 281474976710656) { //max 48 bits (6 bytes)
                    if (this.mac48Dictionary.ContainsKey(mac48)) {
                        macVendor = this.mac48Dictionary[mac48];
                        return true;
                    }
                    else if (this.mac36Dictinoary.ContainsKey(mac48 >> 12)) {
                        macVendor = this.mac36Dictinoary[mac48 >> 12];
                        return true;
                    }
                    else if (this.mac24Dictionary.ContainsKey(mac48 >> 24)) {
                        macVendor = this.mac24Dictionary[mac48 >> 24];
                        return true;
                    }
                    else {
                        macVendor = null;
                        return false;
                    }
                }
                else
                    throw new Exception("Incorrect MAC address: " + macAddress);
            }
            else
                throw new Exception("Incorrect MAC address: " + macAddress);
            /*
            else {
                string macKey = macAddress.Substring(0, 2) + ":" + macAddress.Substring(3, 2) + ":" + macAddress.Substring(6, 2);
                if (macPrefixDictionary.ContainsKey(macKey)) {
                    macVendor = macPrefixDictionary[macKey];
                    return true;
                }
                else if (macFullDictionary.ContainsKey(macAddress)) {
                    macVendor = macFullDictionary[macAddress];
                    return true;
                }
                else {
                    macVendor = null;
                    return false;
                }
            }
            */
        }

    }
}
