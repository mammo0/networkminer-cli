using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.PacketHandlers {
    public class RtpPacketHandler : AbstractPacketHandler, IPacketHandler {

        //https://en.wikipedia.org/wiki/RTP_audio_video_profile
        public enum RtpPayloadType : byte {
            //maybe also add G722, L8 and L16 whcih all have fixed bits/sample
            //G729 is more common than those ones though, followed by G723 : https://www.cisco.com/c/en/us/support/docs/voice/voice-quality/7934-bwidth-consume.html

            G711_PCM_U = 0,//ITU-T G.711 PCM µ-Law audio 64 kbit/s
            //GSM610 = 3,//European GSM Full Rate audio 13 kbit/s (GSM 06.10)
            G711_PCM_A = 8,//ITU-T G.711 PCM A-Law audio 64 kbit/s
            G722 = 9,//ITU-T G.722 SB-ADPCM audio 64 kbit/s 	RFC 3551
            G729 = 18
            
            //AppleAirPlay = 96//Dynamic RTP type 96
        }

        //internal System.Collections.Concurrent.ConcurrentQueue<Tuple<System.Net.IPAddress, System.Net.IPAddress, ushort>> NewRtpEndPoints { get; }


        private const int MAX_AUDIO_STREAMS = 2000;//2000. was originally 100, which would limit number of calls to ~50
        private PopularityList<Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, RtpPayloadType>, AudioStream> audioStreams;

        public override Type[] ParsedTypes { get; } = { typeof(Packets.RtpPacket) };

        public RtpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.audioStreams = new PopularityList<Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, RtpPayloadType>, AudioStream>(MAX_AUDIO_STREAMS);
            //this.NewRtpEndPoints = new System.Collections.Concurrent.ConcurrentQueue<Tuple<System.Net.IPAddress, System.Net.IPAddress, ushort>>();

            this.audioStreams.PopularityLost += (t, a) => a.Dispose();//will remove the associated temp file
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            Packets.UdpPacket udpPacket = null;
            

            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.UdpPacket))
                    udpPacket = (Packets.UdpPacket)p;
                else if(udpPacket != null && p is Packets.RtpPacket rtpPacket) {
                    //Packets.RtpPacket rtpPacket =(Packets.RtpPacket)p;
                    if(Enum.IsDefined(typeof(RtpPayloadType), rtpPacket.PayloadType)) {
                        RtpPayloadType payloadType = (RtpPayloadType)rtpPacket.PayloadType;
                        FiveTuple fiveTuple = new FiveTuple(sourceHost, udpPacket.SourcePort, destinationHost, udpPacket.DestinationPort, FiveTuple.TransportProtocol.UDP);
                        
                        AudioStream audioStream;
                        Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, RtpPayloadType> key = new Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, RtpPayloadType>(sourceHost.IPAddress, udpPacket.SourcePort, destinationHost.IPAddress, udpPacket.DestinationPort, payloadType);
                        if (this.audioStreams.ContainsKey(key))
                            audioStream = this.audioStreams[key];
                        else {

                            audioStream = new AudioStream(sourceHost, destinationHost, payloadType, MainPacketHandler.FileStreamAssemblerList, fiveTuple, rtpPacket.ParentFrame.FrameNumber);
                            this.audioStreams.Add(key, audioStream);
                            base.MainPacketHandler.OnAudioDetected(audioStream);
                        }

                        audioStream.AddSamples(rtpPacket.ParentFrame.Data.Skip(rtpPacket.PacketStartIndex).Take(rtpPacket.PacketByteCount).Skip(Packets.RtpPacket.HEADER_LENGTH).ToArray(), rtpPacket.SampleTick, rtpPacket.ParentFrame.Timestamp, rtpPacket.SyncSourceID);
                    }
                }
            }
        }

        public void Reset() {
            foreach (var audioStream in this.audioStreams.GetValueEnumerator())
                audioStream.Dispose();
            this.audioStreams = new PopularityList<Tuple<System.Net.IPAddress, ushort, System.Net.IPAddress, ushort, RtpPayloadType>, AudioStream>(MAX_AUDIO_STREAMS);
        }

        #endregion
    }
}
