//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class TlsRecordPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        /**
         * TLS records fragmentation, i.e. objects fragmented into multiple TLS records:
         * 
         * multiple client messages of the same ContentType MAY be coalesced
         * into a single TLSPlaintext record, or a single message MAY be
         * fragmented across several records
         * https://tools.ietf.org/html/rfc5246#section-6.2.1
         **/
        private PopularityList<FiveTuple, Tuple<List<Packets.TlsRecordPacket>, List<Packets.TlsRecordPacket>>> tlsRecordFragmentCache;

        private Dictionary<string, string> ja3Fingerprints;

        public override Type ParsedType { get { return typeof(Packets.TlsRecordPacket); } }

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Ssl; }
        }

        public TlsRecordPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {

            this.tlsRecordFragmentCache = new PopularityList<FiveTuple, Tuple<List<Packets.TlsRecordPacket>, List<Packets.TlsRecordPacket>>>(100);
            this.ja3Fingerprints = Fingerprints.Ja3FingerprintDictionaryFactory.CreateDictionary(base.MainPacketHandler.FingerprintsPath + "ja3fingerprint.json");
        }

        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            bool successfulExtraction = false;


            Packets.TcpPacket tcpPacket = null;
            foreach (Packets.AbstractPacket p in packetList)
                if (p.GetType() == typeof(Packets.TcpPacket))
                    tcpPacket = (Packets.TcpPacket)p;
            int parsedBytes = 0;
            if (tcpPacket != null) {

                //there might be several TlsRecordPackets in an SSL packet
                foreach (Packets.AbstractPacket p in packetList) {
                    if (p is Packets.TlsRecordPacket tlsRecordPacket) {
                        if (tlsRecordPacket.TlsRecordIsComplete) {
                            //check for previous fragments (see RFC 5246 section 6.2.1)
                            List<Packets.TlsRecordPacket> recordList = null;
                            lock (this.tlsRecordFragmentCache) {
                                if (this.tlsRecordFragmentCache.ContainsKey(tcpSession.Flow.FiveTuple)) {
                                    if (transferIsClientToServer)
                                        recordList = this.tlsRecordFragmentCache[tcpSession.Flow.FiveTuple].Item1;
                                    else
                                        recordList = this.tlsRecordFragmentCache[tcpSession.Flow.FiveTuple].Item2;
                                    if (recordList != null && recordList.Count > 0 && recordList[0].ContentType != tlsRecordPacket.ContentType)
                                        recordList.Clear();
                                }
                                else {
                                    recordList = new List<Packets.TlsRecordPacket>();
                                    if (transferIsClientToServer)
                                        this.tlsRecordFragmentCache.Add(tcpSession.Flow.FiveTuple, new Tuple<List<Packets.TlsRecordPacket>, List<Packets.TlsRecordPacket>>(recordList, new List<Packets.TlsRecordPacket>()));
                                    else
                                        this.tlsRecordFragmentCache.Add(tcpSession.Flow.FiveTuple, new Tuple<List<Packets.TlsRecordPacket>, List<Packets.TlsRecordPacket>>(new List<Packets.TlsRecordPacket>(), recordList));
                                }
                                if (recordList != null) {
                                    recordList.Add(tlsRecordPacket);
                                }
                            }
                            if (recordList != null) {

                                if (tlsRecordPacket.ContentType == Packets.TlsRecordPacket.ContentTypes.Handshake) {
                                    int parsedHandshakesTotalLength = 0;

                                    foreach (Packets.TlsRecordPacket.HandshakePacket handshake in Packets.TlsRecordPacket.HandshakePacket.GetHandshakes(recordList)) {
                                        parsedHandshakesTotalLength += handshake.PacketLength;
                                        this.ExtractData(tcpPacket, tcpSession.Flow.FiveTuple, transferIsClientToServer, handshake);
                                    }

                                    this.RemoveParsedTlsRecordsFromList(recordList, parsedHandshakesTotalLength, tcpPacket);
                                }
                                //TODO add handlers for other TLS record content types here...
                                else if (tlsRecordPacket.ContentType == Packets.TlsRecordPacket.ContentTypes.Application) {
                                    //encrypted application data

                                    recordList.Clear();//let's not store encrypted data in memory unless it can be decrypted
                                }
                                else if (recordList.Count > 3)//limit stored records of unparsed types in order to save memory
                                    recordList.Clear();
                            }
                            successfulExtraction = true;
                            parsedBytes += tlsRecordPacket.Length + 5;//Same as tlsRecordPacket.PacketLength
                        }
                        else if (tlsRecordPacket.Length > 16384) {//rfc5246 says records are max 0x4000 bytes, so just skip it... there is no point in reassembling it any more
                            successfulExtraction = true;
                            parsedBytes = tcpPacket.PayloadDataLength;
                        }
                    }
                }
            }

            if (successfulExtraction) {
                return parsedBytes;
                //return tcpPacket.PayloadDataLength;
            }
            else
                return 0;
        }

        private void RemoveParsedTlsRecordsFromList(List<Packets.TlsRecordPacket> recordList, int parsedBytes, Packets.TcpPacket tcpPacket) {
            if (parsedBytes > 0) {
                //remove the parsed TLS records from the recordList
                int accumulatedRecordLength = 0;
                for (int i = 0; i < recordList.Count; i++) {
                    accumulatedRecordLength += recordList[i].Length;
                    if (accumulatedRecordLength >= parsedBytes) {
                        if (accumulatedRecordLength > parsedBytes) {
                            base.MainPacketHandler.OnAnomalyDetected(new PacketParser.Events.AnomalyEventArgs("TLS data boundary is not on a TLS record boundary in frame " + tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp));
#if DEBUG
                            System.Diagnostics.Debugger.Break();
#endif
                        }
                        recordList.RemoveRange(0, i + 1);
                        break;
                    }
                }
            }
        }

        public void Reset() {
            //close all resources
            this.tlsRecordFragmentCache.Clear();
        }

        #endregion


        private void ExtractData(Packets.TcpPacket tcpPacket, FiveTuple fiveTuple, bool transferIsClientToServer, Packets.TlsRecordPacket.HandshakePacket handshake) {

            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = fiveTuple.ClientHost;
                destinationHost = fiveTuple.ServerHost;
            }
            else {
                sourceHost = fiveTuple.ServerHost;
                destinationHost = fiveTuple.ClientHost;
            }

            //foreach (Packets.AbstractPacket p in tlsRecordPacket.GetSubPackets(false)) {
            //    if(p.GetType()==typeof(Packets.TlsRecordPacket.HandshakePacket)) {
            //        Packets.TlsRecordPacket.HandshakePacket handshake=(Packets.TlsRecordPacket.HandshakePacket)p;
            foreach (var version in handshake.GetSupportedSslVersions()) {
                //destinationHost.AddHostName(handshake.ServerHostName);
                System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection {
                            { "TLS Handshake " + Enum.GetName(typeof(Packets.TlsRecordPacket.HandshakePacket.MessageTypes), handshake.MessageType) + " Supported Version", version.Item1.ToString() + "." + version.Item2.ToString() + " (0x" + version.Item1.ToString("x2") + version.Item2.ToString("x2") + ")" }
                        };
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Handshake"));

            }
            if (!String.IsNullOrEmpty(handshake.GetAlpnNextProtocolString())) {
                //destinationHost.AddHostName(handshake.ServerHostName);
                System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection {
                            { "TLS ALPN", handshake.GetAlpnNextProtocolString() }
                        };
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Handshake"));

            }
            if (handshake.MessageType == Packets.TlsRecordPacket.HandshakePacket.MessageTypes.ClientHello) {
                System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection();
                param.Add("JA3 Signature", handshake.GetJA3FingerprintFull());
                string ja3Hash = handshake.GetJA3FingerprintHash();
                if(this.ja3Fingerprints.ContainsKey(ja3Hash))
                    sourceHost.AddJA3Hash(ja3Hash, this.ja3Fingerprints[ja3Hash]);
                else
                    sourceHost.AddJA3Hash(ja3Hash);
                param.Add("JA3 Hash", ja3Hash);
                if (handshake.ServerHostName != null) {
                    destinationHost.AddHostName(handshake.ServerHostName);
                    param.Add("TLS Server Name (SNI)", handshake.ServerHostName);
                }
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Client Hello"));
            }
            else if (handshake.MessageType == Packets.TlsRecordPacket.HandshakePacket.MessageTypes.Certificate)
                for (int i = 0; i < handshake.CertificateList.Count; i++) {
                    byte[] certificate = handshake.CertificateList[i];
                    string x509CertSubject;
                    System.Security.Cryptography.X509Certificates.X509Certificate x509Cert = null;
                    try {
                        x509Cert = new System.Security.Cryptography.X509Certificates.X509Certificate(certificate);
                        x509CertSubject = x509Cert.Subject;
                    }
                    catch {
                        x509CertSubject = "Unknown_x509_Certificate_Subject";
                        x509Cert = null;
                    }
                    if (x509CertSubject.Contains("CN="))
                        x509CertSubject = x509CertSubject.Substring(x509CertSubject.IndexOf("CN=") + 3);
                    else if (x509CertSubject.Contains("="))
                        x509CertSubject = x509CertSubject.Substring(x509CertSubject.IndexOf('=') + 1);
                    if (x509CertSubject.Length > 28)
                        x509CertSubject = x509CertSubject.Substring(0, 28);
                    if (x509CertSubject.Contains(","))
                        x509CertSubject = x509CertSubject.Substring(0, x509CertSubject.IndexOf(','));

                    x509CertSubject.Trim(new char[] { '.', ' ' });
                    /*
                    while (x509CertSubject.EndsWith(".") || x509CertSubject.EndsWith(" "))
                        x509CertSubject=x509CertSubject.Substring(0, x509CertSubject.Length-1);
                        */
                    string filename = x509CertSubject + ".cer";
                    string fileLocation = "/";
                    string details;
                    if (x509Cert != null)
                        details = "TLS Certificate: " + x509Cert.Subject;
                    else
                        details = "TLS Certificate: Unknown x509 Certificate";


                    FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(base.MainPacketHandler.FileStreamAssemblerList, fiveTuple, transferIsClientToServer, FileTransfer.FileStreamTypes.TlsCertificate, filename, fileLocation, certificate.Length, certificate.Length, details, null, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.source);
                    base.MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                    if (i == 0 && x509CertSubject.Contains(".") && !x509CertSubject.Contains("*") && !x509CertSubject.Contains(" "))
                        sourceHost.AddHostName(x509CertSubject);
                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                    //parameters.Add("Certificate Subject", x509Cert.Subject);
                    const string CERTIFICATE_SUBJECT = "Certificate Subject";
                    this.addParameters(parameters, x509Cert.Subject, CERTIFICATE_SUBJECT);
                    if (i == 0) {
                        //check for CN parameter
                        if (parameters[CERTIFICATE_SUBJECT + " CN"] != null) {
                            foreach (string cn in parameters.GetValues(CERTIFICATE_SUBJECT + " CN")) {
                                sourceHost.AddNumberedExtraDetail("X.509 Certificate Subject CN", cn);
                                if (cn.Contains(".") && !cn.Contains(" ")) {
                                    if (cn.Contains("*")) {
                                        if (cn.StartsWith("*."))
                                            sourceHost.AddDomainName(cn.Substring(2));
                                    }
                                    else
                                        sourceHost.AddHostName(cn);
                                }
                            }
                        }
                    }

                    this.addParameters(parameters, x509Cert.Issuer, "Certificate Issuer");



                    //parameters.Add("Certificate Issuer", x509Cert.Issuer);
                    parameters.Add("Certificate Hash", x509Cert.GetCertHashString());
                    parameters.Add("Certificate valid from", x509Cert.GetEffectiveDateString());
                    parameters.Add("Certificate valid to", x509Cert.GetExpirationDateString());
                    parameters.Add("Certificate Serial", x509Cert.GetSerialNumberString());
                    try {
                        System.Security.Cryptography.X509Certificates.X509Certificate2 cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate);
                        foreach (var ext in cert2.Extensions) {
                            string fn = ext.Oid.FriendlyName;
                            string oid = ext.Oid.Value;
                            string val = ext.Format(true);
                            System.IO.StringReader sr = new System.IO.StringReader(val);
                            string line = sr.ReadLine();
                            while (line != null) {
                                parameters.Add(oid + " " + fn, line);
                                if (i == 0 && oid == "2.5.29.17") {
                                    sourceHost.AddNumberedExtraDetail("X.509 Certificate " + fn, line);
                                }
                                line = sr.ReadLine();
                            }
                        }

                        if (cert2.Verify())
                            parameters.Add("Certificate valid", "TRUE");
                        else
                            parameters.Add("Certificate valid", "FALSE");

                    }
                    catch (Exception) { }


                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, parameters, tcpPacket.ParentFrame.Timestamp, "X.509 Certificate"));

                    if (assembler.TryActivate())
                        assembler.AddData(certificate, tcpPacket.SequenceNumber);//this one should trigger FinnishAssembling()
                }
            //}
            //return true;
        }

        private void addParameters(System.Collections.Specialized.NameValueCollection parameters, string x509Subject, string parameterName) {
            foreach(string part in x509Subject.Split(new char[] { ',' }))
                if(part.Contains("=")) {
                    parameters.Add(parameterName + " " + part.Substring(0, part.IndexOf('=')).Trim(), part.Substring(part.IndexOf('=') + 1).Trim());
                }
        }
    }
}
