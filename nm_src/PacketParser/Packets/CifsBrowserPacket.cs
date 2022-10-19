using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets
{
    class CifsBrowserPacket : AbstractPacket {

        enum BrowserMessageOpCode : byte {
            HostAnnouncement = 0x01,
            AnnouncementRequest = 0x02,
            RequestElection = 0x08,
            GetBackupListRequest = 0x09,
            GetBackupListResponse = 0x0A,
            BecomeBackup = 0x0B,
            DomainAnnouncement = 0x0C,
            MasterAnnouncement = 0x0D,
            ResetStateRequest = 0x0E,
            LocalMasterAnnouncement = 0x0F
        }

        byte Command { get; }
        string CommandName {
            get {
                if (Enum.IsDefined(typeof(BrowserMessageOpCode), this.Command))
                    return Enum.GetName(typeof(BrowserMessageOpCode), this.Command);
                else
                    return String.Empty;
            }
        }
        public (byte major, byte minor) OSVersion { get; }
        public string DomainOrWorkgroup { get; } = null;
        public string Hostname { get; } = null;
        public string Comment { get; } = null;
        public TimeSpan? Uptime { get; } = null;

        //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/d2d83b29-4b62-479e-b427-9b750303387b
        internal CifsBrowserPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "MS-BRWS (CIFS Browser Protocol)") {
            this.Command = parentFrame.Data[packetStartIndex];
            if (this.Command == (byte)BrowserMessageOpCode.DomainAnnouncement) {
                int index = packetStartIndex + 6;
                this.DomainOrWorkgroup = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index, false, false, 16);
                //this.OSVersion = (parentFrame.Data[this.PacketStartIndex + 22], parentFrame.Data[this.PacketStartIndex + 23]);
                index = this.PacketStartIndex + 32;
                if (index < packetEndIndex)
                    this.Hostname = Utils.ByteConverter.ReadNullTerminatedString(ParentFrame.Data, ref index, false, false, 43);
            }
            else if (this.Command == (byte)BrowserMessageOpCode.LocalMasterAnnouncement || this.Command == (byte)BrowserMessageOpCode.HostAnnouncement) {
                //ServerName (16 bytes): MUST be a null-terminated ASCII server name with a length of 16 bytes, including the null terminator. If the name is fewer than 16 bytes in length including the terminator, then the remainder of the 16 bytes must be ignored. 
                int index = packetStartIndex + 6;
                this.Hostname = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index, false, false, 16);
                //this.OSVersion = (parentFrame.Data[this.PacketStartIndex + 18], parentFrame.Data[this.PacketStartIndex + 19]);
                this.OSVersion = (parentFrame.Data[this.PacketStartIndex + 22], parentFrame.Data[this.PacketStartIndex + 23]);
                //Comment (variable): A null-terminated ASCII string that MUST be less than or equal to 43 bytes in length, including the null terminator. This is a purely informational comment associated with the server and has no effect on the operation of the CIFS Browser Protocol. 
                index = PacketStartIndex + 32;
                if(index < packetEndIndex)
                    this.Comment = Utils.ByteConverter.ReadNullTerminatedString(ParentFrame.Data, ref index, false, false, 43);
            }
            else if (this.Command == (byte)BrowserMessageOpCode.RequestElection) {
                //Uptime (4 bytes): An unsigned 32-bit integer that MUST be the number of seconds since the browser service was started on the server. 
                this.Uptime = new TimeSpan(0, 0, (int)Utils.ByteConverter.ToUInt32(ParentFrame.Data, packetStartIndex + 6, 4, true));

                //ServerName (16 bytes): MUST be a null-terminated ASCII server name with a length of 16 bytes, including the null terminator. If the name is fewer than 16 bytes in length including the terminator, then the remainder of the 16 bytes must be ignored. 
                int index = packetStartIndex + 14;
                this.Hostname = Utils.ByteConverter.ReadNullTerminatedString(parentFrame.Data, ref index, false, false, 16);
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            yield break;
        }
    }
}
