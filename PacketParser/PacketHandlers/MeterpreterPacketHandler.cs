using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class MeterpreterPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public override Type ParsedType { get { return typeof(Packets.MeterpreterPacket); } }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.Meterpreter;
            }
        }

        private readonly PopularityList<FiveTuple, FileTransfer.FileStreamAssembler> fileStreamAssemblers;

        public MeterpreterPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.fileStreamAssemblers = new PopularityList<FiveTuple, FileTransfer.FileStreamAssembler>(100);
        }

        

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            int bytesHandled = 0;
            foreach (Packets.MeterpreterPacket p in packetList.OfType<MeterpreterPacket>()) {
                bytesHandled += p.ParsedBytesCount;

                if (p.PayloadLength > 0) {
                    FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, transferIsClientToServer, FileTransfer.FileStreamTypes.Meterpreter, "meterpreter.payload", String.Empty, "PAYLOAD=reverse_tcp LPORT="+tcpSession.ServerTcpPort, p.ParentFrame.FrameNumber, p.ParentFrame.Timestamp);
                    assembler.FileContentLength = p.PayloadLength;
                    assembler.FileSegmentRemainingBytes = p.PayloadLength;
                    lock(this.fileStreamAssemblers)
                        this.fileStreamAssemblers.Add(tcpSession.Flow.FiveTuple, assembler);
                    base.MainPacketHandler.FileStreamAssemblerList.AddOrEnqueue(assembler);
                    //assembler.TryActivate();
                }
                else if(p.HasMZHeader) {
                    if (this.fileStreamAssemblers.ContainsKey(tcpSession.Flow.FiveTuple)) {
                        //var assembler = base.MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer);
                        lock (this.fileStreamAssemblers) {
                            var assembler = this.fileStreamAssemblers[tcpSession.Flow.FiveTuple];
                            if (assembler != null && !assembler.IsActive) {
                                assembler.Filename = "meterpreter.dll";
                                assembler.TryActivate();
                            }
                        }
                    }
                        
                }
            }
            return bytesHandled;
        }

        public void Reset() {
            //throw new NotImplementedException();
        }
    }
}
