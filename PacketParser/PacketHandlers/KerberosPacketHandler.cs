using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class KerberosPacketHandler : AbstractPacketHandler, IPacketHandler, ITcpSessionPacketHandler {
        
        private IUdpPayloadProtocolFinder udpPayloadProtocolFinder;
        private static readonly HashSet<string> usernameRequestPaths = new HashSet<string>(new[] { "6a.30.a4.30.a1.30.a1.30" });
        private static readonly HashSet<string> usernameResponsePaths = new HashSet<string>(new[] { "6b.30.a4.30.a1.30", "6d.30.a4.30.a1.30" });
        private static readonly HashSet<string> hostnameRequestPaths = new HashSet<string>(new[] { "6a.30.a4.30.a1.30.a1.30", "6c.30.a4.30.a3.30.a1.30" });
        private static readonly HashSet<string> hostnameResponsePaths = new HashSet<string>(new[] { "6b.30.a4.30.a1.30", "6d.30.a4.30.a1.30", "6d.30.a5.61.30.a2.30.a1.30" });
        private static readonly HashSet<string> domainPaths = new HashSet<string>(new[] {
            "6a.30.a4.30.a2",
            "6c.30.a4.30.a2",
            "6c.30.a4.30.ab.30.61.30.a1",
            "6d.30.a3",//crealm
            "6d.30.a5.61.30.a1",
            "7e.30.a9" });//kerberos.realm of requests and responses

        private static readonly HashSet<string> krbAsRepTicketPaths = new HashSet<string>(new[] {
            //"6b.30.a5.61.30.a3.30.a2",//this hash doesn't work
            "6b.30.a6.30.a2"
        });

        private static readonly HashSet<Utils.ByteConverter.Asn1TypeTag> stringTypes = new HashSet<Utils.ByteConverter.Asn1TypeTag>(new[] {
            Utils.ByteConverter.Asn1TypeTag.CharacterString,
            Utils.ByteConverter.Asn1TypeTag.GeneralString,
            Utils.ByteConverter.Asn1TypeTag.ISO646String,
            Utils.ByteConverter.Asn1TypeTag.PrintableString,
            Utils.ByteConverter.Asn1TypeTag.UniversalString,
            Utils.ByteConverter.Asn1TypeTag.UTF8String
        });

        //private readonly PopularityList<int, TicketPrimitives> ticketPrimitivesList;
        private readonly PopularityList<int, string> saltList;

        public override Type ParsedType { get { return typeof(KerberosPacket); } }

        public KerberosPacketHandler(PacketHandler mainPacketHandler, IUdpPayloadProtocolFinder udpPayloadProtocolFinder = null)
            : base(mainPacketHandler) {
            this.udpPayloadProtocolFinder = udpPayloadProtocolFinder;
            //this.ticketPrimitivesList = new PopularityList<int, TicketPrimitives>(100);
            this.saltList = new PopularityList<int, string>(100);
        }

        public ApplicationLayerProtocol HandledProtocol {
            get {
                return ApplicationLayerProtocol.Kerberos;
            }
        }

        #region IPacketHandler Members

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            //throw new NotImplementedException();
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.ClientHost;
                destinationHost = tcpSession.ServerHost;
            }
            else {
                sourceHost = tcpSession.ServerHost;
                destinationHost = tcpSession.ClientHost;
            }
            return this.ExtractData(sourceHost, destinationHost, packetList);
        }

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            this.ExtractData(sourceHost, destinationHost, packetList);
        }
        public int ExtractData(NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            int parsedBytes = 0;
            Packets.ITransportLayerPacket transportLayerPacket = null;
            
            
            foreach (Packets.AbstractPacket p in packetList) {
                if (p is ITransportLayerPacket)
                    transportLayerPacket = p as ITransportLayerPacket;
                if (p.GetType() == typeof(Packets.KerberosPacket)) {
                    Packets.KerberosPacket kerberosPacket = (Packets.KerberosPacket)p;

                    //TicketPrimitives sessionTicketPrimitives = null;
                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();

                    string sessionSalt = this.GetKrbErrorSalt(kerberosPacket);//returns null in none found
                    if(sessionSalt != null) {
                        parameters.Add("Kerberos Salt", sessionSalt);
                    }
                    int hostPairHash = sourceHost.IPAddress.GetHashCode() ^ destinationHost.IPAddress.GetHashCode();
                    if (this.saltList.ContainsKey(hostPairHash))
                        if(sessionSalt == null)
                            sessionSalt = this.saltList[hostPairHash];
                        else
                            this.saltList[hostPairHash] = sessionSalt;
                    else if(sessionSalt != null) {
                        this.saltList.Add(hostPairHash, sessionSalt);
                    }
                        

                    

                    //parameters.Add("Kerberos message type", Enum.GetName(typeof(KerberosPacket.MessageType), kerberosPacket.MsgType) + " ("+((int)kerberosPacket.MsgType).ToString()+")");


                    List<uint> packetIntegers = new List<uint>();
                    byte encryptionType = 0;
                    //uint lastInteger = 0;
                    //List<string> spnParts = new List<string>();
                    List<(string username, string hash)> kerberosHashes = new List<(string username, string hash)>();
                    //string username, realm;
                    (string username, string realm) = this.GetUserAndRealm(kerberosPacket, sourceHost, destinationHost);
                    if(!string.IsNullOrEmpty(username))
                        parameters.Add("Kerberos Username", username);
                    if(!string.IsNullOrEmpty(realm))
                        parameters.Add("Kerberos Realm", realm);

                    foreach (var item in kerberosPacket.AsnData) {
                       
                        if (item.Item2 == Utils.ByteConverter.Asn1TypeTag.Integer) {
                            //lastInteger = Utils.ByteConverter.ToUInt32(item.Item3);
                            uint number = Utils.ByteConverter.ToUInt32(item.Item3);
                            packetIntegers.Add(number);
                            if(kerberosPacket.MsgType == KerberosPacket.MessageType.krb_tgs_rep && item.Item1.Equals("6d.30.a5.61.30.a3.30.a0")) {
                                encryptionType = (byte)number;

                            }
                            else if(kerberosPacket.MsgType == KerberosPacket.MessageType.krb_as_rep) {
                                if(item.Item1.Equals("6b.30.a5.61.30.a3.30.a0") || item.Item1.Equals("6b.30.a6.30.a0"))
                                    encryptionType = (byte)number;
                            }
                        }
                        else if(item.Item2 == Utils.ByteConverter.Asn1TypeTag.OctetString) {

                            //string hexValue = Utils.ByteConverter.ReadHexString(item.Item3, item.Item3.Length, true);
                            if (kerberosPacket.MsgType == KerberosPacket.MessageType.krb_as_req) {
                                if (item.Item1 == "6a.30.a3.30.30.a2" && packetIntegers.Last() == (ushort)KerberosPacket.PADataType.ENC_TIMESTAMP) {
                                    foreach (var encTimestampItem in Utils.ByteConverter.GetAsn1Data(item.Item3)) {
                                        if (encTimestampItem.Item2 == Utils.ByteConverter.Asn1TypeTag.Integer && encTimestampItem.Item1 == "30.a0" && encTimestampItem.Item3.Length == 1) {
                                            encryptionType = encTimestampItem.Item3.First();
                                        }
                                        else if (encTimestampItem.Item2 == Utils.ByteConverter.Asn1TypeTag.OctetString && encTimestampItem.Item1 == "30.a2") {
                                            //sessionTicketPrimitives.Data = Utils.ByteConverter.ReadHexString(encTimestampItem.Item3, encTimestampItem.Item3.Length, true);
                                            //if (sessionTicketPrimitives.TryGetTicketHash(kerberosPacket.MsgType, encryptionType, encTimestampItem.Item3, out string hash))
                                            //    kerberosHashes.Add(hash);
                                            byte[] data = encTimestampItem.Item3;
                                            //krb5pa

                                            //user:$krb5pa$etype$user$realm$salt$HexTimestampHexChecksum

                                            //des:$krb5pa$23$des$DENYDC$$32d396a914a4d0a78e979ba75d4ff53c1db7294141760fee05e434c12ecf8d5b9aa5839e09a2244893aff5f384f79c37883f154a
                                            //des:$krb5pa$3$des$DENYDC$DENYDC.COMdes$233b4272aa93727221facfdbdcc9d1d9a0c43a2798c810600310c0daf48fb969c26cb47d69f575a65e00163845f68811f9c5266271cc0f91
                                            //u5:$krb5pa$23$u5$DENYDC$DENYDC.COMdes$daf324dccec73739f6e49ef8fde60a9f9dfff50551ff5a7e969c6e395f18b842fb17c3b503df3025ab5a9dfc3031e893c4002008
                                            //u5:$krb5pa$23$u5$DENYDC$DENYDC.COMdes$addbe67ccf9dd3c3da9e233612816c5720447ae202cfe7a84a719e1ef70b93bcef49786f71319a93d60531fcb443f7e96039f540

                                            StringBuilder sb = new StringBuilder();
                                            //sb.Append(username);
                                            //sb.Append(":$krb5pa$");
                                            sb.Append("$krb5pa$");
                                            sb.Append(encryptionType);
                                            sb.Append("$");
                                            sb.Append(username);
                                            sb.Append("$");
                                            sb.Append(realm);
                                            sb.Append("$");
                                            sb.Append(sessionSalt);
                                            sb.Append("$");
                                            if (encryptionType == 23) {
                                                //string checksum = Data.Substring(0, 32);
                                                string checksum = Utils.ByteConverter.ReadHexString(data, 16, 0, true);
                                                //string encTimestamp = Data.Substring(32);
                                                string encTimestamp = Utils.ByteConverter.ReadHexString(data, data.Length - 16, 16, true);
                                                //"%s:$krb5pa$%s$%s$%s$%s$%s%s\n" % (user, etype, user, realm, salt, enc_timestamp, checksum)
                                                sb.Append(encTimestamp);
                                                sb.Append(checksum);
                                            }
                                            else //"%s:$krb5pa$%s$%s$%s$%s$%s\n" % (user, etype, user, realm, salt, PA_DATA_ENC_TIMESTAMP)
                                                sb.Append(Utils.ByteConverter.ReadHexString(data, data.Length, true));
                                            kerberosHashes.Add((username, sb.ToString()));
                                        }
                                    }
                                }
                            }
                            else if (kerberosPacket.MsgType == KerberosPacket.MessageType.krb_tgs_rep) {
                                if (item.Item1 == "6d.30.a5.61.30.a3.30.a2" &&
                                encryptionType == 23 &&
                                packetIntegers.Count > 2 && packetIntegers.Skip(packetIntegers.Count - 2).First() == 23) {

                                    byte[] data = item.Item3;
                                    //sessionTicketPrimitives.Username = string.Join("/", spnParts);
                                    //if (sessionTicketPrimitives.TryGetTicketHash(kerberosPacket.MsgType, encryptionType, item.Item3, out string hash))
                                    //    kerberosHashes.Add(hash);
                                    //$krb5tgs$<ENCRYPTION_TYPE>$*<USERNAME>$<REALM>$<SPN>*$<FIRST_16_BYTES_TICKET>$<REMAINING_TICKET_BYTES>
                                    //"%s:$krb5tgs$%s$%s$%s\n" % (spn, etype, data[:32], data[32:])
                                    StringBuilder sb = new StringBuilder();
                                    //sb.Append(username);
                                    //sb.Append(":$krb5tgs$");
                                    sb.Append("$krb5tgs$");
                                    sb.Append(encryptionType);
                                    sb.Append("$");
                                    string encPart1 = Utils.ByteConverter.ReadHexString(data, 16, 0, true);
                                    string encPart2 = Utils.ByteConverter.ReadHexString(data, data.Length - 16, 16, true);
                                    sb.Append(encPart1);
                                    sb.Append("$");
                                    sb.Append(encPart2);
                                    kerberosHashes.Add((username, sb.ToString()));
                                    //sessionTicketPrimitives.Data = Utils.ByteConverter.ReadHexString(item.Item3, item.Item3.Length, true);
                                }
                            }
                            else if (kerberosPacket.MsgType == KerberosPacket.MessageType.krb_as_rep) {
                                if (krbAsRepTicketPaths.Contains(item.Item1)) {
                                    byte[] data = item.Item3;
                                    //TODO: create kerberosHash
                                    StringBuilder sb = new StringBuilder();
                                    
                                    sb.Append("$krb5asrep$");
                                    sb.Append(encryptionType);
                                    sb.Append("$");
                                    if (string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(sessionSalt)) {
                                        username = sessionSalt;
                                    }
                                    if (encryptionType == 23) {
                                        //sys.stdout.write("$krb5asrep$%s$%s$%s\n" % (etype, data[0:32], data[32:]))
                                        string encPart1 = Utils.ByteConverter.ReadHexString(data, 16, 0, true);
                                        string encPart2 = Utils.ByteConverter.ReadHexString(data, data.Length - 16, 16, true);
                                        sb.Append(encPart1);
                                        sb.Append("$");
                                        sb.Append(encPart2);
                                        kerberosHashes.Add((username, sb.ToString()));
                                    }
                                    else if(!string.IsNullOrEmpty(sessionSalt)) {
                                        //if etype != "23":
                                        //sys.stdout.write("$krb5asrep$%s$%s$%s$%s\n" % (etype, salt, data[0:-24], data[-24:]))
                                        sb.Append(sessionSalt);
                                        sb.Append("$");
                                        string encPart1 = Utils.ByteConverter.ReadHexString(data, 12, 0, true);
                                        string encPart2 = Utils.ByteConverter.ReadHexString(data, data.Length - 12, 12, true);
                                        sb.Append(encPart1);
                                        sb.Append("$");
                                        sb.Append(encPart2);
                                        kerberosHashes.Add((username, sb.ToString()));
                                    }

                                }
                            }
                            
                        }
                        
                    }
                    foreach(var h in kerberosHashes) {
                        string hashUser = h.username;
                        //string hashUser = hash.Split(new char[] { ':', '$' }).First();
                        if (string.IsNullOrEmpty(hashUser)) {
                            if (!string.IsNullOrEmpty(username))
                                hashUser = username;
                            else if (!string.IsNullOrEmpty(sessionSalt))
                                hashUser = sessionSalt;
                            else
                                hashUser = "<UNKNOWN>";
                        }
                        
                        if(kerberosPacket.IsRequest)
                            base.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "Kerberos", hashUser, h.hash, kerberosPacket.ParentFrame.Timestamp));
                        else
                            base.MainPacketHandler.AddCredential(new NetworkCredential(destinationHost, sourceHost, "Kerberos", hashUser, h.hash, kerberosPacket.ParentFrame.Timestamp));
                        
                    }
                    /*
                    string krbHash = sessionTicketPrimitives.GetTicketHash(kerberosPacket.MsgType);
                    if (krbHash != null)
                        base.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "Kerberos", sessionTicketPrimitives.Username, krbHash, kerberosPacket.ParentFrame.Timestamp, sessionTicketPrimitives.Realm));
                    */
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(kerberosPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, transportLayerPacket.TransportProtocol, transportLayerPacket.SourcePort, transportLayerPacket.DestinationPort, parameters, kerberosPacket.ParentFrame.Timestamp, "Kerberos " + Enum.GetName(typeof(KerberosPacket.MessageType), kerberosPacket.MsgType)));
                    parsedBytes += kerberosPacket.PacketLength;
                }

            }
            return parsedBytes;
        }

        private string GetKrbErrorSalt(KerberosPacket kerberosPacket) {
            if (kerberosPacket.MsgType == KerberosPacket.MessageType.krb_error) {//30
                foreach (var item in kerberosPacket.AsnData.Where(item => item.Item2 == Utils.ByteConverter.Asn1TypeTag.OctetString)) {
                    foreach (var errorItem in Utils.ByteConverter.GetAsn1Data(item.Item3).Where(ei => ei.Item2 == Utils.ByteConverter.Asn1TypeTag.OctetString && ei.Item1 == "30.30.a2")) {
                        foreach (var entry in Utils.ByteConverter.GetAsn1Data(errorItem.Item3).Where(ei => ei.Item2 == Utils.ByteConverter.Asn1TypeTag.OctetString && ei.Item1 == "30.30.a1")) {
                            string salt;
                            try {
                                salt = Utils.ByteConverter.ReadString(entry.Item3);
                                if (salt.Length == entry.Item3.Length) {
                                    return salt;
                                }
                            }
                            catch(Exception e) {
                                SharedUtils.Logger.Log("Error extracting kerberos salt from OctetString (30.30.a1): " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                            }
                            //backup is to save salt as hex
                            return Utils.ByteConverter.ReadHexString(entry.Item3, entry.Item3.Length, true);
                        }

                    }
                }
            }
            else if (kerberosPacket.MsgType == KerberosPacket.MessageType.krb_as_rep) {
                //Extract salt from packets matching "kerberos.padata_type == 3"
                foreach (var item in kerberosPacket.AsnData.Where(item => item.Item2 == Utils.ByteConverter.Asn1TypeTag.OctetString && item.Item1 == "6b.30.a2.30.30.a2")) {
                    string salt;
                    foreach (var saltItem in Utils.ByteConverter.GetAsn1Data(item.Item3).Where(si => si.Item2 == Utils.ByteConverter.Asn1TypeTag.GeneralString && si.Item1 == "30.30.a1")) {
                        try {
                            salt = Utils.ByteConverter.ReadString(saltItem.Item3);
                            if (salt.Length == saltItem.Item3.Length) {
                                return salt;//only return the first matching element
                            }
                        }
                        catch(Exception e) {
                            SharedUtils.Logger.Log("Error extracting kerberos salt from GeneralString: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                        }
                    }
                    //If no GeneralString is found, try to extract salt from the OctetString data
                    try {
                        salt = Utils.ByteConverter.ReadString(item.Item3);
                        if (salt.Length == item.Item3.Length) {
                            return salt;
                        }
                    }
                    catch(Exception e){
                        SharedUtils.Logger.Log("Error extracting kerberos salt from OctetString: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    }
                    //backup is to save salt as hex
                    return Utils.ByteConverter.ReadHexString(item.Item3, item.Item3.Length, true);
                }
            }
            return null;
        }

        private (string username, string realm) GetUserAndRealm(KerberosPacket kerberosPacket, NetworkHost sourceHost, NetworkHost destinationHost) {
            string username = "";
            string realm = "";
            List<string> spnParts = new List<string>();
            foreach (var item in kerberosPacket.AsnData.Where(item => stringTypes.Contains(item.Item2))) {
                string itemString = Utils.ByteConverter.ReadString(item.Item3);


                if (item.Item2 == Utils.ByteConverter.Asn1TypeTag.GeneralString && hostnameRequestPaths.Contains(item.Item1) && itemString.EndsWith("$")) {
                    string hostname = itemString.TrimEnd(new[] { '$' });
                    sourceHost.AddHostName(hostname);
                    //parameters.Add("Hostname (" + item.Item1 + ")", hostname);
                    realm = hostname;
                }
                else if (item.Item2 == Utils.ByteConverter.Asn1TypeTag.GeneralString && hostnameResponsePaths.Contains(item.Item1) && itemString.EndsWith("$")) {
                    string hostname = itemString.TrimEnd(new[] { '$' });
                    destinationHost.AddHostName(hostname);
                    //parameters.Add("Hostname (" + item.Item1 + ")", hostname);
                    realm = hostname;
                }
                else if (item.Item2 == Utils.ByteConverter.Asn1TypeTag.GeneralString && (usernameRequestPaths.Contains(item.Item1) || usernameResponsePaths.Contains(item.Item1)) && !itemString.EndsWith("$")) {
                    if (usernameRequestPaths.Contains(item.Item1)) {
                        base.MainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "Kerberos", itemString, kerberosPacket.ParentFrame.Timestamp));
                        sourceHost.AddNumberedExtraDetail("Kerberos Username", itemString);
                        username = itemString;
                    }
                    else if (usernameResponsePaths.Contains(item.Item1)) {
                        base.MainPacketHandler.AddCredential(new NetworkCredential(destinationHost, sourceHost, "Kerberos", itemString, kerberosPacket.ParentFrame.Timestamp));
                        destinationHost.AddNumberedExtraDetail("Kerberos Username", itemString);
                        username = itemString;
                    }
#if DEBUG
                    else
                        System.Diagnostics.Debugger.Break();
#endif


                    //parameters.Add("Username (" + item.Item1 + ")", username);
                }
                else if (item.Item2 == Utils.ByteConverter.Asn1TypeTag.GeneralString && domainPaths.Contains(item.Item1)) {
                    sourceHost.AddDomainName(itemString);
                    destinationHost.AddDomainName(itemString);
                    //parameters.Add("Realm (" + item.Item1 + ")", itemString);
                    realm = itemString;
                }
                else if (item.Item2 == Utils.ByteConverter.Asn1TypeTag.GeneralString && kerberosPacket.MsgType == KerberosPacket.MessageType.krb_tgs_rep && hostnameResponsePaths.Contains(item.Item1))
                    spnParts.Add(itemString);
                else {
                    //parameters.Add(item.Item1 + " " + Enum.GetName(typeof(Utils.ByteConverter.Asn1TypeTag), item.Item2), itemString);
                }
            }
            if(kerberosPacket.MsgType == KerberosPacket.MessageType.krb_tgs_rep && spnParts.Count > 0)
                username = string.Join("/", spnParts);
            return (username, realm);
        }

        public void Reset() {
            this.saltList.Clear();
        }

        #endregion
    }
}
