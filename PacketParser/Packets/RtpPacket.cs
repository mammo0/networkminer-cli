using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://www.ietf.org/rfc/rfc1889.txt
    public class RtpPacket : AbstractPacket{


        public enum RTPVersion { VAT = 0, Draft = 1, RFC1889 = 2, v3 = 3 }

        internal RTPVersion RtpVersion { get; }
        internal const int HEADER_LENGTH = 12;

        /// <summary>
        /// If the padding bit is set, the packet contains one or more
        /// additional padding octets at the end which are not part of the
        /// payload.The last octet of the padding contains a count of how
        /// many padding octets should be ignored.Padding may be needed by
        /// some encryption algorithms with fixed block sizes or for
        /// carrying several RTP packets in a lower - layer protocol data
        /// unit.
        /// </summary>
        internal bool Padding { get; }
        internal bool Extension { get; }
        internal byte CsrcCount { get; }
        internal bool Marker { get; }

        /// <summary>
        /// This field identifies the format of the RTP payload and determines its interpretation by the application. A profile
        /// specifies a default static mapping of payload type codes to payload formats. Additional payload type codes may be defined
        /// dynamically through non-RTP means. An initial set of default mappings for audio and video is specified in the
        /// companion profile Internet-Draft draft-ietf-avt-profile, and may be extended in future editions of the Assigned Numbers RFC.
        /// An RTP sender emits a single RTP payload type at any given time; this field is not intended for multiplexing separate media streams
        /// </summary>
        internal byte PayloadType { get; } //https://en.wikipedia.org/wiki/RTP_audio_video_profile
        internal ushort SequenceNumber { get; }
        internal uint SampleTick { get; }
        internal uint SyncSourceID { get; }

        internal RtpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "RTP") {
            this.RtpVersion = (RTPVersion)(parentFrame.Data[packetStartIndex] >> 6);
            this.Padding = (parentFrame.Data[packetStartIndex] & 0x20) == 0x20;
            this.Extension = (parentFrame.Data[packetStartIndex] & 0x10) == 0x10;
            this.CsrcCount = (byte)(parentFrame.Data[packetStartIndex] & 0x0f);

            this.Marker = (parentFrame.Data[packetStartIndex + 1] >> 7) == 1;
            this.PayloadType = (byte)(parentFrame.Data[packetStartIndex + 1] & 0x7f);

            this.SequenceNumber = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false);
            this.SampleTick = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
            this.SyncSourceID = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8);
            //the remaining part (packetStartIndex + 12) is the source/payload/CSRC
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //throw new Exception("The method or operation is not implemented.");
            yield break;//no sub packets
        }
    }
}
