using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IVoipCallHandler {
        void PacketHandler_AudioDetected(PacketParser.AudioStream audioStream);
        void PacketHandler_VoipCallDetected(System.Net.IPAddress ipA, ushort portA, System.Net.IPAddress ipB, ushort portB, string callId, string from, string to);

        IEnumerable<NetworkMiner.VoipCall> GetVoipCalls(Func<DateTime, string> toCustomTimeZoneStringFunction);
    }
}
