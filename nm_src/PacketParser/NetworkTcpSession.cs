//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using SharedUtils;
using System;
using System.Collections.Generic;

namespace PacketParser {
    public class NetworkTcpSession : IComparable, IComparable<NetworkTcpSession> {//only TCP sessions


        private readonly long startFrameNumber;
        private bool finPacketReceived;
        private uint clientToServerFinPacketSequenceNumber;
        private uint serverToClientFinPacketSequenceNumber;
        private bool? requiredNextTcpDataStreamIsClientToServer = null;
        private readonly Func<DateTime, string> toCustomTimeZoneStringFunction;
        private readonly List<EventHandler<Frame>> sessionClosedHandlers;

        //public event OnSessionClosed;
        public event EventHandler<Frame> OnSessionClosed {
            add {
                this.sessionClosedHandlers.Add(value);
            }
            remove {
                this.sessionClosedHandlers.Remove(value);
            }
        }
        public NetworkHost ClientHost { get { return this.Flow.FiveTuple.ClientHost; } }
        public NetworkHost ServerHost { get { return this.Flow.FiveTuple.ServerHost; } }
        public ushort ClientTcpPort { get { return this.Flow.FiveTuple.ClientPort; } }
        public ushort ServerTcpPort { get { return this.Flow.FiveTuple.ServerPort; } }
        public DateTime StartTime { get { return this.Flow.StartTime; } }//in NetworkFlow
        public DateTime EndTime { get { return this.Flow.EndTime; } }//in NetworkFlow
        public bool SynPacketReceived { get; private set; }
        public bool SynAckPacketReceived { get; private set; }
        public bool FinPacketReceived {
            get {
                //https://sourceforge.net/projects/networkminer/forums/forum/665610/topic/4946533/index/page/1
                return this.finPacketReceived &&
                    (this.ClientToServerTcpDataStream == null ||
                    this.ServerToClientTcpDataStream == null ||
                    this.ClientToServerTcpDataStream == null ||
                    (this.clientToServerFinPacketSequenceNumber <= this.ClientToServerTcpDataStream.ExpectedTcpSequenceNumber && this.serverToClientFinPacketSequenceNumber < this.ServerToClientTcpDataStream.ExpectedTcpSequenceNumber));
            }
        }
        public bool SessionEstablished { get; private set; }
        public bool SessionClosed { get; private set; }
        public TcpDataStream ClientToServerTcpDataStream { get; private set; }
        public TcpDataStream ServerToClientTcpDataStream { get; private set; }
        public TcpDataStream RequiredNextTcpDataStream {
            get {
                if (this.requiredNextTcpDataStreamIsClientToServer == true)
                    return this.ClientToServerTcpDataStream;
                else if (this.requiredNextTcpDataStreamIsClientToServer == false)
                    return this.ServerToClientTcpDataStream;
                else
                    return null;
            }
            set {
                if (value == null)
                    this.requiredNextTcpDataStreamIsClientToServer = null;
            }
        }
        public ISessionProtocolFinder ProtocolFinder { get; set; }
        public NetworkFlow Flow { get; }

        private NetworkTcpSession(Func<DateTime, string> toCustomTimeZoneStringFunction) {
            this.toCustomTimeZoneStringFunction = toCustomTimeZoneStringFunction;
            this.sessionClosedHandlers = new List<EventHandler<Frame>>();
        }

        public NetworkTcpSession(Packets.TcpPacket tcpSynPacket, NetworkHost clientHost, NetworkHost serverHost, ISessionProtocolFinderFactory protocolFinderFactory, Func<DateTime, string> toCustomTimeZoneStringFunction) : this(toCustomTimeZoneStringFunction) {
            //this.toCustomTimeZoneStringFunction = toCustomTimeZoneStringFunction;
            //this.sessionClosedHandlers = new List<EventHandler<Frame>>();

            if (tcpSynPacket.FlagBits.Synchronize) {//It's normal to start the session with a SYN flag
                FiveTuple fiveTuple = new FiveTuple(clientHost, tcpSynPacket.SourcePort, serverHost, tcpSynPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpSynPacket.ParentFrame.Timestamp, tcpSynPacket.ParentFrame.Timestamp, 0, 0);

                this.SynPacketReceived = false;
                this.SynAckPacketReceived = false;
                this.finPacketReceived = false;
                this.clientToServerFinPacketSequenceNumber = UInt32.MaxValue;
                this.serverToClientFinPacketSequenceNumber = UInt32.MaxValue;
                this.SessionEstablished = false;
                this.SessionClosed = false;

                this.startFrameNumber = tcpSynPacket.ParentFrame.FrameNumber;

                this.ClientToServerTcpDataStream = null;
                this.ServerToClientTcpDataStream = null;


                this.ProtocolFinder = protocolFinderFactory.CreateProtocolFinder(this.Flow, this.startFrameNumber);
            }
            else
                throw new Exception("SYN flag not set on TCP packet");

        }
        /// <summary>
        /// Creates a truncated TCP session where the initial 3 way handshake is missing
        /// </summary>
        /// <param name="sourceHost"></param>
        /// <param name="destinationHost"></param>
        /// <param name="tcpPacket"></param>
        public NetworkTcpSession(NetworkHost sourceHost, NetworkHost destinationHost, Packets.TcpPacket tcpPacket, ISessionProtocolFinderFactory protocolFinderFactory, Func<DateTime, string> toCustomTimeZoneStringFunction) : this(toCustomTimeZoneStringFunction) {
            //this part is used to create a cropped (truncated) session where the beginning is missing!
            //this.toCustomTimeZoneStringFunction = toCustomTimeZoneStringFunction;
            this.SynPacketReceived = true;
            this.SynAckPacketReceived = true;
            this.finPacketReceived = false;
            this.SessionEstablished = false;//I will change this one soon,...
            this.SessionClosed = false;

            this.startFrameNumber = tcpPacket.ParentFrame.FrameNumber;

            this.ClientToServerTcpDataStream = null;
            this.ServerToClientTcpDataStream = null;


            //now let's do a qualified guess of who is the server and who is client...

            FiveTuple fiveTuple;
            List<ApplicationLayerProtocol> sourcePortProtocols = new List<ApplicationLayerProtocol>(TcpPortProtocolFinder.GetProbableApplicationLayerProtocols(tcpPacket.SourcePort, tcpPacket.SourcePort));
            List<ApplicationLayerProtocol> destinationPortProtocols = new List<ApplicationLayerProtocol>(TcpPortProtocolFinder.GetProbableApplicationLayerProtocols(tcpPacket.DestinationPort, tcpPacket.DestinationPort));
            if (sourcePortProtocols.Count > destinationPortProtocols.Count) { //packet is server -> client
                fiveTuple = new FiveTuple(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.AcknowledgmentNumber, tcpPacket.SequenceNumber);

            }
            else if (destinationPortProtocols.Count > 0) { //packet is client -> server
                fiveTuple = new FiveTuple(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
            }
            else if (tcpPacket.SourcePort < tcpPacket.DestinationPort) {//packet is server -> client
                fiveTuple = new FiveTuple(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.AcknowledgmentNumber, tcpPacket.SequenceNumber);
            }
            else {//packet is client -> server
                fiveTuple = new FiveTuple(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.Flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
            }

            this.ProtocolFinder = protocolFinderFactory.CreateProtocolFinder(this.Flow, this.startFrameNumber);
        }



        public string GetFlowID() {
            return this.ClientHost.IPAddress.ToString() + ":" + this.ClientTcpPort.ToString() + "-" + this.ServerHost.IPAddress.ToString() + ":" + this.ServerTcpPort.ToString();
        }

        public static int GetHashCode(NetworkHost clientHost, NetworkHost serverHost, ushort clientTcpPort, ushort serverTcpPort) {
            int cHash = clientHost.IPAddress.GetHashCode() ^ clientTcpPort;
            int sHash = serverHost.IPAddress.GetHashCode() ^ serverTcpPort;
            return cHash ^ (sHash << 16) ^ (sHash >> 16);//this should be enough in order to avoid collisions
        }

        public override int GetHashCode() {
            return GetHashCode(this.ClientHost, this.ServerHost, this.ClientTcpPort, this.ServerTcpPort);
        }
        public override string ToString() {
            long serverBytes = 0;
            long clientBytes = 0;
            if (this.ServerToClientTcpDataStream != null)
                serverBytes = this.ServerToClientTcpDataStream.TotalByteCount;
            if (this.ClientToServerTcpDataStream != null)
                clientBytes = this.ClientToServerTcpDataStream.TotalByteCount;

            string endTime, startTime;
            if (this.toCustomTimeZoneStringFunction != null) {
                startTime = this.toCustomTimeZoneStringFunction(this.Flow.StartTime);
                endTime = this.toCustomTimeZoneStringFunction(this.Flow.EndTime);
            }
            else {
                startTime = this.Flow.StartTime.ToString();
                endTime = this.Flow.EndTime.ToString();
            }

            return "Server: " + this.ServerHost.ToString() + " TCP " + this.ServerTcpPort + " (" + serverBytes + " data bytes sent), Client: " + this.ClientHost.ToString() + " TCP " + this.ClientTcpPort + " (" + clientBytes + " data bytes sent), Session start: " + startTime + ", Session end: " + endTime;
        }

        public bool TryAddPacket(Packets.TcpPacket tcpPacket, NetworkHost sourceHost, NetworkHost destinationHost) {
            if (this.SessionClosed)
                return false;

            //Make sure the hosts are correct
            if (sourceHost == this.ClientHost && tcpPacket.SourcePort == this.ClientTcpPort) {//client -> server
                if (destinationHost != this.ServerHost)
                    return false;
                if (tcpPacket.SourcePort != this.ClientTcpPort)
                    return false;
                if (tcpPacket.DestinationPort != this.ServerTcpPort)
                    return false;
            }
            else if (sourceHost == this.ServerHost && tcpPacket.SourcePort == this.ServerTcpPort) {//server -> client
                if (destinationHost != ClientHost)
                    return false;
                if (tcpPacket.SourcePort != ServerTcpPort)
                    return false;
                if (tcpPacket.DestinationPort != ClientTcpPort)
                    return false;
            }
            else//unknown direction
                return false;

            this.Flow.EndTime = tcpPacket.ParentFrame.Timestamp;

            //Check TCP handshake
            if (!this.SynPacketReceived) {//SYN (client->server)
                if (tcpPacket.FlagBits.Synchronize && sourceHost == this.ClientHost)
                    this.SynPacketReceived = true;
                else
                    return false;
            }
            else if (!this.SynAckPacketReceived) {//SYN+ACK (server->client)
                if (tcpPacket.FlagBits.Synchronize && tcpPacket.FlagBits.Acknowledgement && sourceHost == this.ServerHost)
                    this.SynAckPacketReceived = true;
                else
                    return false;
            }
            else if (!this.SessionEstablished) {//ACK (client->server)
                if (tcpPacket.FlagBits.Acknowledgement && sourceHost == this.ClientHost) {
                    this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
                }
                else
                    return false;
            }
            //FIN and RST is handeled further down 


            //an established and not closed session!
            if (tcpPacket.PayloadDataLength > 0) {
                this.ProtocolFinder.AddPacket(tcpPacket, sourceHost, destinationHost);
                try {
                    //If we've come this far the packet should be allright for the networkSession
                    byte[] tcpSegmentData = tcpPacket.GetTcpPacketPayloadData();


                    //now add the data to the server to calculate service statistics for the open port
                    NetworkServiceMetadata networkServiceMetadata = null;
                    lock (this.ServerHost.NetworkServiceMetadataList) {
                        if (!this.ServerHost.NetworkServiceMetadataList.ContainsKey(this.ServerTcpPort)) {
                            networkServiceMetadata = new NetworkServiceMetadata(this.ServerHost, this.ServerTcpPort);
                            this.ServerHost.NetworkServiceMetadataList.Add(this.ServerTcpPort, networkServiceMetadata);
                        }
                        else
                            networkServiceMetadata = this.ServerHost.NetworkServiceMetadataList[this.ServerTcpPort];
                    }

                    //now, lets extract some data from the TCP packet!
                    if (sourceHost == this.ServerHost && tcpPacket.SourcePort == this.ServerTcpPort) {
                        networkServiceMetadata.OutgoingTraffic.AddTcpPayloadData(tcpSegmentData);
                        if (this.ServerToClientTcpDataStream == null)
                            this.ServerToClientTcpDataStream = new TcpDataStream(tcpPacket.SequenceNumber, false, this);
                        if (this.requiredNextTcpDataStreamIsClientToServer == null && this.ServerToClientTcpDataStream.TotalByteCount == 0)
                            this.requiredNextTcpDataStreamIsClientToServer = false;
                        this.ServerToClientTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData, tcpPacket.FlagBits);
                    }
                    else {
                        networkServiceMetadata.IncomingTraffic.AddTcpPayloadData(tcpSegmentData);
                        if (this.ClientToServerTcpDataStream == null)
                            this.ClientToServerTcpDataStream = new TcpDataStream(tcpPacket.SequenceNumber, true, this);
                        if (this.requiredNextTcpDataStreamIsClientToServer == null && this.ClientToServerTcpDataStream.TotalByteCount == 0)
                            this.requiredNextTcpDataStreamIsClientToServer = true;
                        this.ClientToServerTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData, tcpPacket.FlagBits);
                    }
                }
                catch (Exception ex) {
                    SharedUtils.Logger.Log("Error parsing TCP session data in " + tcpPacket.ParentFrame.ToString() + ". " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                    if (!tcpPacket.ParentFrame.QuickParse)
                        tcpPacket.ParentFrame.Errors.Add(new Frame.Error(tcpPacket.ParentFrame, tcpPacket.PacketStartIndex, tcpPacket.PacketEndIndex, ex.Message));
                    return false;
                }
            }

            //se if stream should be closed
            if (tcpPacket.FlagBits.Reset) {//close no matter what
                this.Close(tcpPacket.ParentFrame);
            }
            else if (tcpPacket.FlagBits.Fin) {//close nicely
                if (!this.finPacketReceived) {
                    this.finPacketReceived = true;
                    if (sourceHost == this.ServerHost && tcpPacket.SourcePort == this.ServerTcpPort)
                        this.serverToClientFinPacketSequenceNumber = tcpPacket.SequenceNumber;
                    else
                        this.clientToServerFinPacketSequenceNumber = tcpPacket.SequenceNumber;
                }
                else if (tcpPacket.FlagBits.Acknowledgement)//fin+ack
                    this.Close(tcpPacket.ParentFrame);
            }

            return true;
        }


        internal void RemoveData(TcpDataStream.VirtualTcpData virtualTcpData, NetworkHost sourceHost, ushort sourceTcpPort) {
            this.RemoveData(virtualTcpData.FirstPacketSequenceNumber, virtualTcpData.ByteCount, sourceHost, sourceTcpPort);

        }

        internal void RemoveData(uint firstSequenceNumber, int bytesToRemove, NetworkHost sourceHost, ushort sourceTcpPort) {
            if (sourceHost == this.ServerHost && sourceTcpPort == this.ServerTcpPort)
                this.ServerToClientTcpDataStream.RemoveData(firstSequenceNumber, bytesToRemove);
            else if (sourceHost == this.ClientHost && sourceTcpPort == this.ClientTcpPort)
                this.ClientToServerTcpDataStream.RemoveData(firstSequenceNumber, bytesToRemove);
            else
                throw new Exception("NetworkHost is not part of the NetworkTcpSession");
        }

        private void SetEstablished(uint clientInitialSequenceNumber, uint serverInitialSequenceNumber) {
            this.SessionEstablished = true;
            if (this.ClientToServerTcpDataStream == null)
                this.ClientToServerTcpDataStream = new TcpDataStream(clientInitialSequenceNumber, true, this);
            else
                this.ClientToServerTcpDataStream.InitialTcpSequenceNumber = clientInitialSequenceNumber;
            if (this.ServerToClientTcpDataStream == null)
                this.ServerToClientTcpDataStream = new TcpDataStream(serverInitialSequenceNumber, false, this);
            else
                this.ServerToClientTcpDataStream.InitialTcpSequenceNumber = serverInitialSequenceNumber;
            lock (this.ServerHost.IncomingSessionList)
                this.ServerHost.IncomingSessionList.Add(this);
            lock (this.ClientHost.OutgoingSessionList)
                this.ClientHost.OutgoingSessionList.Add(this);

        }

        internal void Close(Frame lastFrame = null) {
            if (!this.SessionClosed) {
                this.SessionClosed = true;

                if (this.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.Unknown)
                    this.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.Unknown, false);

                try {
                    foreach (var eh in this.sessionClosedHandlers) {
                        eh(this, lastFrame);
                    }
                }
                catch (Exception e) {
                    Logger.DebugLog("Error closing NetworkTcpSession: " + e);
                }
            }
        }


        #region IComparable Members

        public int CompareTo(NetworkTcpSession session) {
            if (this.ClientHost.CompareTo(session.ClientHost) != 0)
                return this.ClientHost.CompareTo(session.ClientHost);
            else if (this.ServerHost.CompareTo(session.ServerHost) != 0)
                return this.ServerHost.CompareTo(session.ServerHost);
            else if (this.ClientTcpPort != session.ClientTcpPort)
                return this.ClientTcpPort - session.ClientTcpPort;
            else if (this.ServerTcpPort != session.ServerTcpPort)
                return this.ServerTcpPort - session.ServerTcpPort;
            else if (this.StartTime.CompareTo(session.StartTime) != 0)
                return this.StartTime.CompareTo(session.StartTime);
            else
                return 0;
        }

        public int CompareTo(object obj) {
            NetworkTcpSession s = (NetworkTcpSession)obj;
            return this.CompareTo(s);
        }

        #endregion

        public class TcpDataStream {
            private readonly System.Collections.Generic.SortedList<uint, byte[]> dataList;
            private bool dataListIsTruncated = false;

            private VirtualTcpData virtualTcpData;
            private readonly NetworkTcpSession session;
            private readonly NetworkFlow networkFlow;
            private readonly bool streamIsClientToServer;

            public long TotalByteCount {
                get {
                    if (this.streamIsClientToServer)
                        return this.networkFlow.BytesSentClient;
                    else
                        return this.networkFlow.BytesSentServer;
                }
                set {
                    if (this.streamIsClientToServer)
                        this.networkFlow.BytesSentClient = value;
                    else
                        this.networkFlow.BytesSentServer = value;
                }
            }
            public int DataSegmentBufferCount { get { return this.dataList.Count; } }
            public int DataSegmentBufferMaxSize { get; }

            internal uint InitialTcpSequenceNumber { get; set; }
            internal uint ExpectedTcpSequenceNumber { get; private set; }


            public TcpDataStream(uint initialTcpSequenceNumber, bool streamIsClientToServer, NetworkTcpSession session) {
                this.InitialTcpSequenceNumber = initialTcpSequenceNumber;
                this.ExpectedTcpSequenceNumber = initialTcpSequenceNumber;
                this.dataList = new SortedList<uint, byte[]>();
                this.DataSegmentBufferMaxSize = 1024;//Increased buffer size 2020-08-14 in order to support network traffic from poor quality links with lots of retransmissions

                this.virtualTcpData = null;
                this.session = session;
                this.networkFlow = session.Flow;
                this.streamIsClientToServer = streamIsClientToServer;
            }

            [Obsolete]
            internal bool HasMissingSegments() {
                return this.TotalByteCount < this.ExpectedTcpSequenceNumber - this.InitialTcpSequenceNumber;
            }

            internal void Clear() {
                this.dataList.Clear();
            }

            public void AddTcpData(uint tcpSequenceNumber, byte[] tcpSegmentData, Packets.TcpPacket.Flags tcpFlags) {

                if (tcpSegmentData.Length > 0) {//It is VERY important that no 0 length data arrays are added! There is otherwise a big risk for getting stuck in forever-loops etc.

                    //ensure that only new data is written to the dataList
                    //partially overlapping resent frames are handled here
                    if ((int)(this.ExpectedTcpSequenceNumber - tcpSequenceNumber) > 0 && ExpectedTcpSequenceNumber - tcpSequenceNumber < tcpSegmentData.Length) {
                        //remove the stuff that has already been parsed
                        uint bytesToSkip = this.ExpectedTcpSequenceNumber - tcpSequenceNumber;
                        byte[] newSegmentData = new byte[tcpSegmentData.Length - bytesToSkip];
                        Array.Copy(tcpSegmentData, bytesToSkip, newSegmentData, 0, newSegmentData.Length);
                        tcpSegmentData = newSegmentData;
                        tcpSequenceNumber += bytesToSkip;
                    }
                    //see if we've missed part of the handshake and are now seeing the first data with lower sequence number
                    if (this.TotalByteCount == 0 && this.InitialTcpSequenceNumber == this.ExpectedTcpSequenceNumber && (int)(ExpectedTcpSequenceNumber - tcpSequenceNumber) > 0 && (int)(tcpSequenceNumber - ExpectedTcpSequenceNumber) < 12345) {
                        this.InitialTcpSequenceNumber = tcpSequenceNumber;
                        this.ExpectedTcpSequenceNumber = tcpSequenceNumber;
                    }
                    //A check that the tcpSequenceNumber is a reasonable one, i.e. not smaller than expected and not too large
                    if ((int)(this.ExpectedTcpSequenceNumber - tcpSequenceNumber) <= 0 && tcpSequenceNumber - ExpectedTcpSequenceNumber < 1234567) {



                        if (!this.dataList.ContainsKey(tcpSequenceNumber)) {

                            //handle partially overlapping TCP segments that have arrived previously
                            IList<uint> tcpSequenceNumbers = this.dataList.Keys;
                            //we wanna know if we already have an already stored sequence nr. where: new tcpSeqNr < stored tcpSeqNr < new tcpSeqNr + new tcpSeqData.Length


                            for (int i = tcpSequenceNumbers.Count - 1; i >= 0; i--) {
                                if (tcpSequenceNumbers[i] < tcpSequenceNumber)
                                    break;
                                else if (tcpSequenceNumbers[i] < tcpSequenceNumber + tcpSegmentData.Length) {
                                    //we need to truncate the data since parts of it has already been received
                                    uint bytesToKeep = tcpSequenceNumbers[i] - tcpSequenceNumber;
                                    byte[] newSegmentData = new byte[bytesToKeep];
                                    Array.Copy(tcpSegmentData, 0, newSegmentData, 0, bytesToKeep);
                                    tcpSegmentData = newSegmentData;
                                }
                            }
                            //A keepalive contains 0 or 1 bytes of data and has a sequence nr that is next_expected-1, never SYN/FIN/RST
                            //Avoid adding TCP data for TCP-keepalives with "fake" one-byte L7 data (null value)
                            if (tcpSegmentData.Length > 1 || tcpSegmentData[0] != 0 || this.TotalByteCount > 0 || tcpFlags.Push) {
                                this.dataList.Add(tcpSequenceNumber, tcpSegmentData);
                                this.TotalByteCount += tcpSegmentData.Length;
                            }
#if DEBUG
                            else if (tcpSegmentData.Length == 1 && tcpSegmentData[0] == 0) {
                                //likely TCP keepalive packet here
                            }
#endif

                            if (this.ExpectedTcpSequenceNumber == tcpSequenceNumber) {
                                this.ExpectedTcpSequenceNumber += (uint)tcpSegmentData.Length;
                                //check if there are other packets that arrived too early that follows this packet
                                while (this.dataList.ContainsKey(this.ExpectedTcpSequenceNumber))
                                    this.ExpectedTcpSequenceNumber += (uint)this.dataList[ExpectedTcpSequenceNumber].Length;
                            }

                            while (this.dataList.Count > this.DataSegmentBufferMaxSize) {
                                if (!this.dataListIsTruncated) {
                                    SharedUtils.Logger.Log("Too many unparsed queued packets, queue will be truncated for : " + this.networkFlow.FiveTuple.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
#if DEBUG
                                    if (!debugHasBreaked) {
                                        System.Diagnostics.Debugger.Break();
                                        debugHasBreaked = true;
                                    }
#endif
                                }
                                this.dataList.RemoveAt(0);//remove the oldest TCP data
                                this.dataListIsTruncated = true;
                                this.virtualTcpData = null;//this one has to be reset so that the virtualPacket still will work
                            }
                        }
                        else {//let's replace the old TCP packet with the new one
                            //Or maybe just skip it!
                        }
                    }
                }
            }

#if DEBUG
            static bool debugHasBreaked = false;
#endif


            /// <summary>
            /// Counts the number of bytes which are ready for reading (that is are in the correct order).
            /// Time complexity = O(1)
            /// </summary>
            /// <returns></returns>
            public int CountBytesToRead() {
                if (dataList.Count < 1)
                    return 0;
                else {
                    return (int)this.ExpectedTcpSequenceNumber - (int)this.dataList.Keys[0];
                }
            }

            /// <summary>
            /// Counts the number of packets from the start that are in one complete sequence
            /// Time complexity = O(nPacketsInSequence)
            /// </summary>
            /// <returns></returns>
            public int CountPacketsToRead() {
                //this method does not always return dataList.Count since some packets in the dataList might be out of order or missing

                if (dataList.Count == 0)
                    return 0;
                else {
                    int nPackets = 0;
                    uint nextSequenceNumber = dataList.Keys[0];
                    foreach (KeyValuePair<uint, byte[]> pair in this.dataList)
                        if (pair.Key == nextSequenceNumber) {
                            nPackets++;
                            nextSequenceNumber += (uint)pair.Value.Length;
                        }
                        else
                            break;
                    return nPackets;
                }
            }

            internal VirtualTcpData GetAllAvailableTcpData() {
                this.GetNextVirtualTcpData();
                this.virtualTcpData.AppendAllAvailablePackets();
                return this.virtualTcpData;
            }

            internal VirtualTcpData GetNextVirtualTcpData() {
                if (this.virtualTcpData == null) {
                    if (this.dataList.Count > 0 && this.CountBytesToRead() > 0 && this.CountPacketsToRead() > 0) {
                        if (this.streamIsClientToServer)
                            this.virtualTcpData = new VirtualTcpData(this, this.networkFlow.FiveTuple.ClientPort, this.networkFlow.FiveTuple.ServerPort);
                        else
                            this.virtualTcpData = new VirtualTcpData(this, this.networkFlow.FiveTuple.ServerPort, this.networkFlow.FiveTuple.ClientPort);
                        return virtualTcpData;
                    }
                    else
                        return null;
                }
                else if (this.virtualTcpData.TryAppendNextPacket())
                    return this.virtualTcpData;
                else
                    return null;
            }

            /// <summary>
            /// Removes sequenced data from the beginning
            /// </summary>
            /// <param name="bytesToRemove"></param>
            internal void RemoveData(int bytesToRemove) {
                if (this.dataList.Count > 0)
                    this.RemoveData(this.dataList.Keys[0], bytesToRemove);
            }

            internal void RemoveData(VirtualTcpData data) {
                this.RemoveData(data.FirstPacketSequenceNumber, data.ByteCount);
            }

            internal void RemoveData(uint firstSequenceNumber, int bytesToRemove) {
                if (this.dataList.Keys[0] != firstSequenceNumber)
                    throw new Exception("The data (first data sequence number: " + this.dataList.Keys[0] + ") is not equal to " + firstSequenceNumber);
                else {
                    while (this.dataList.Count > 0 && this.dataList.Keys[0] + this.dataList.Values[0].Length <= firstSequenceNumber + bytesToRemove)
                        this.dataList.RemoveAt(0);
                    //see if we need to do a partial removal of a tcp packet
                    if (this.dataList.Count > 0 && this.dataList.Keys[0] < firstSequenceNumber + bytesToRemove) {
                        uint newFirstSequenceNumber = firstSequenceNumber + (uint)bytesToRemove;
                        byte[] oldData = this.dataList.Values[0];
                        byte[] truncatedData = new byte[this.dataList.Keys[0] + oldData.Length - newFirstSequenceNumber];
                        Array.Copy(oldData, oldData.Length - truncatedData.Length, truncatedData, 0, truncatedData.Length);
                        this.dataList.RemoveAt(0);
                        this.dataList.Add(newFirstSequenceNumber, truncatedData);
                    }
                    this.virtualTcpData = null;
                }

            }

            /// <summary>
            /// Enumerates all segments (that are in a complete sequence) and removes them from the NetworkTcpSession.TcpDataStream object
            /// </summary>
            /// <returns></returns>
            public IEnumerable<byte[]> GetSegments() {
                if (dataList.Count < 1)
                    yield break;
                else {
                    for (uint nextSegmentSequenceNumber = dataList.Keys[0]; nextSegmentSequenceNumber < this.ExpectedTcpSequenceNumber; nextSegmentSequenceNumber = dataList.Keys[0]) {
                        byte[] segment;
                        if (dataList.TryGetValue(nextSegmentSequenceNumber, out segment)) {
                            dataList.Remove(dataList.Keys[0]);
                            yield return segment;
                            if (dataList.Count == 0)
                                break;
                        }
                        else {
                            yield break;
                            //break;//this line might not be needed...
                        }
                    }

                }
            }

            internal class VirtualTcpData {
                private readonly TcpDataStream tcpDataStream;
                private readonly ushort sourcePort;
                private readonly ushort destinationPort;

                internal int PacketCount { get; private set; }
                internal int ByteCount {
                    get {
                        return (int)(this.tcpDataStream.dataList.Keys[this.PacketCount - 1] + (uint)this.tcpDataStream.dataList.Values[this.PacketCount - 1].Length - tcpDataStream.dataList.Keys[0]);
                    }
                }
                internal uint FirstPacketSequenceNumber { get { return this.tcpDataStream.dataList.Keys[0]; } }


                internal VirtualTcpData(TcpDataStream tcpDataStream, ushort sourcePort, ushort destinationPort) {
                    this.tcpDataStream = tcpDataStream;
                    this.sourcePort = sourcePort;
                    this.destinationPort = destinationPort;
                    this.PacketCount = 1;
                }

                internal bool TryAppendNextPacket() {

                    int maxPacketFragments = 6;//this one is set low in order to get better performance
                    if (this.tcpDataStream.session.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.SSL)
                        maxPacketFragments = 15; //TLS records are max 16kB, each frame is about 1500 B, 15 frames should be enough (famous last words)
                    if (this.tcpDataStream.session.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.NetBiosSessionService)
                        maxPacketFragments = 1024;//Changed 2011-04-25 to 50, changed 2020-08-14 to 1024
                    else if (this.tcpDataStream.session.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.HTTP)
                        maxPacketFragments = 32;//Changed 2011-10-12 to handle AOL webmail
                    else if (this.tcpDataStream.session.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.SMTP)
                        maxPacketFragments = 61;//Changed 2014-04-07to handle short manual SMTP emails, such as when sending via Telnet (Example: M57 net-2009-11-16-09:24.pcap)
                    else if (this.tcpDataStream.session.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.HTTP2)
                        maxPacketFragments = 22;//Most HTTP/2 sessions use chunks up to 16384 bytes
                    else if (this.tcpDataStream.session.ProtocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.DNS)
                        maxPacketFragments = 55;//Changed 2021-06-01 to handle large TXT records sent over DNS (1-dns.txt.pcap). Normally not more than 46 packets because dns.length is u16 => 46 packets on MTU 1400

                    if (this.tcpDataStream.CountBytesToRead() > this.ByteCount && this.tcpDataStream.CountPacketsToRead() > this.PacketCount && this.PacketCount < maxPacketFragments) {
                        this.PacketCount++;
                        return true;//everything went just fine
                    }
                    else
                        return false;
                }

                internal void AppendAllAvailablePackets() {
                    while (this.tcpDataStream.CountBytesToRead() > this.ByteCount && this.tcpDataStream.CountPacketsToRead() > this.PacketCount) {
                        this.PacketCount++;
                    }
                }

                private byte[] GetTcpHeader() {
                    byte[] tcpHeader = new byte[20];
                    Utils.ByteConverter.ToByteArray(sourcePort, tcpHeader, 0);
                    Utils.ByteConverter.ToByteArray(destinationPort, tcpHeader, 2);
                    Utils.ByteConverter.ToByteArray(tcpDataStream.dataList.Keys[0], tcpHeader, 4);
                    //skip ack.nr.
                    tcpHeader[12] = 0x50;//5 words (5x4=20 bytes) TCP header
                    tcpHeader[13] = 0x18;//flags: ACK+PSH
                    tcpHeader[14] = 0xff;//window size 1
                    tcpHeader[15] = 0xff;//window size 2
                    //calculate TCP checksum!
                    //i'll skip the checksum since I don't have an IP packet (IP source and destination is needed to calculate the checksum

                    //skip urgent pointer
                    return tcpHeader;
                }

                internal byte[] GetBytes(bool prependTcpHeader) {
                    List<byte> dataByteList;
                    if (prependTcpHeader)
                        dataByteList = new List<byte>(GetTcpHeader());
                    else
                        dataByteList = new List<byte>();
                    int tcpHeaderBytes = dataByteList.Count;
                    int packetsInByteList = 0;
#if DEBUG

                    if (this.tcpDataStream.dataList.Count == 0)
                        System.Diagnostics.Debugger.Break();
#endif
                    if (this.tcpDataStream != null && this.tcpDataStream.dataList.Count > 0)
                        for (uint sequenceNumber = this.tcpDataStream.dataList.Keys[0]; packetsInByteList < this.PacketCount; sequenceNumber = this.tcpDataStream.dataList.Keys[0] + (uint)dataByteList.Count - (uint)tcpHeaderBytes) {
                            dataByteList.AddRange(this.tcpDataStream.dataList[sequenceNumber]);//this one will generate an Exception if the sequence number isn't in the list; just as I want it to behave
                            packetsInByteList++;
                        }

                    return dataByteList.ToArray();
                }

            }
        }
    }
}
