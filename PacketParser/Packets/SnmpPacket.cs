using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Security.Cryptography;


namespace PacketParser.Packets {
    internal class SnmpPacket : AbstractPacket {

        internal enum Version : byte { SNMPv1 = 0, SNMPv2c = 1, SNMPv3 = 3 }

        public byte VersionRaw { get; }
        public string CommunityString { get; }
        public List<string> CarvedStrings { get; }

        internal SnmpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "SNMP") {
            //System.Security.Cryptography.AsnEncodedData asnData = new System.Security.Cryptography.AsnEncodedData(parentFrame.Data.Skip(packetStartIndex).Take(base.PacketLength).ToArray());
            //It would be nice if .NET could expose the ASN.1 parser that is built into System.Security.Cryptography.X509Certificates
            //https://github.com/dotnet/corefx/issues/21833
            this.CarvedStrings = new List<string>();

            if (!this.ParentFrame.QuickParse) {
                

                byte[] snmpAsn1Data = parentFrame.Data.Skip(packetStartIndex).Take(base.PacketLength).ToArray();

                int index = 0;
                List<byte[]> b = Utils.ByteConverter.GetAsn1DerSequenceTypes(snmpAsn1Data, ref index, new HashSet<byte>() { 2 });//2 == INTEGER
                if (b.Count > 0 && b[0].Length == 1)
                    this.VersionRaw = b[0][0];

                if (this.VersionRaw == (byte)Version.SNMPv1 || this.VersionRaw == (byte)Version.SNMPv2c) {
                    index = 0;
                    List<string> s = Utils.ByteConverter.ReadAsn1DerSequenceStrings(snmpAsn1Data, ref index);
                    if (s.Count > 0) {
                        this.CommunityString = s[0];
                        this.CarvedStrings.AddRange(s.Skip(1));
                    }
                }
                else if (this.VersionRaw == (byte)Version.SNMPv3) {
                    index = 0;
                    this.CarvedStrings.AddRange(Utils.ByteConverter.ReadAsn1DerSequenceStrings(snmpAsn1Data, ref index));
                }
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            yield break;
        }
    }


}
