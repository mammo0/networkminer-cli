using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Packets {

    //http://www.ietf.org/rfc/rfc3261.txt
    class SipPacket : AbstractPacket {

        /**
         * https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml
         * 
         * ACK 	[RFC3261]
         * BYE 	[RFC3261]
         * CANCEL 	[RFC3261]
         * INFO 	[RFC6086]
         * INVITE 	[RFC3261][RFC6026]
         * MESSAGE 	[RFC3428]
         * NOTIFY 	[RFC6665]
         * OPTIONS 	[RFC3261]
         * PRACK 	[RFC3262]
         * PUBLISH 	[RFC3903]
         * REFER 	[RFC3515]
         * REGISTER 	[RFC3261]
         * SUBSCRIBE 	[RFC6665]
         * UPDATE 	[RFC3311]
         **/
        public enum RequestMethods {
            ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE
        }

        private string messageLine = null;
        private string to = null;
        private string from = null;
        private string callId = null;
        private string contact = null;


        private int contentLength;

        internal string ContentType { get; }
        internal string MessageLine { get { return this.messageLine; } }
        internal string To { get { return this.to; } }
        internal string From { get { return this.from; } }
        internal string Contact { get; } = null;
        internal string CallID { get { return this.callId; } }
        internal SessionDescriptionProtocol SDP { get; }
        internal string UserAgent { get; }
        internal RequestMethods? RequestMethod { get; } = null;
        internal int? ResponseCode { get; } = null;
        internal System.Collections.Specialized.NameValueCollection HeaderFields { get; }

        internal int ContentLength { get { return this.contentLength; } }//aka MessageBodyLength
        internal int MessageBodyStartIndex { get; }


        internal SipPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "SIP") {
            //The first line of the text-encoded message contains the method name
            int index = PacketStartIndex;
            this.HeaderFields = new System.Collections.Specialized.NameValueCollection();
            this.messageLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);

            string requestMethodString = Utils.StringManglerUtil.GetFirstPart(this.messageLine, ' ');
            if (Enum.IsDefined(typeof(RequestMethods), requestMethodString))
                this.RequestMethod = (RequestMethods)Enum.Parse(typeof(RequestMethods), requestMethodString);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Message Line", messageLine);

            string headerLine = "dummy value";
            //System.Collections.Specialized.NameValueCollection headerCollection = new System.Collections.Specialized.NameValueCollection();
            this.ContentType = null;
            while (index < PacketEndIndex && headerLine.Length > 0) {
                headerLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index, true);
                if (headerLine.Contains(":")) {
                    string headerName = headerLine.Substring(0, headerLine.IndexOf(':'));
                    string headerValue = headerLine.Substring(headerLine.IndexOf(':') + 1).Trim();
                    if (headerName.Length > 0 && headerValue.Length > 0) {
                        this.HeaderFields[headerName] = headerValue;

                        if (headerName.Equals("To", StringComparison.InvariantCultureIgnoreCase) || headerName == "t")
                            this.to = headerValue;
                        else if (headerName.Equals("From", StringComparison.InvariantCultureIgnoreCase) || headerName == "f")
                            this.from = headerValue;
                        else if (headerName.Equals("Contact", StringComparison.InvariantCultureIgnoreCase) || headerName == "f")
                            this.Contact = headerValue;
                        else if (headerName.Equals("Call-ID", StringComparison.InvariantCultureIgnoreCase))
                            this.callId = headerValue;
                        else if (headerName.Equals("Contact", StringComparison.InvariantCultureIgnoreCase))
                            this.contact = headerValue;
                        else if (headerName.Equals("Content-Type", StringComparison.InvariantCultureIgnoreCase) || headerName == "c")
                            this.ContentType = headerValue;
                        else if (headerName.Equals("Content-Length", StringComparison.InvariantCultureIgnoreCase) || headerName == "l")
                            Int32.TryParse(headerValue, out this.contentLength);
                        else if (headerName.Equals("User-Agent", StringComparison.InvariantCultureIgnoreCase))
                            this.UserAgent = headerValue;
                    }
                }
            }
            //base.Attributes.Add(headerCollection);

            //the rest is the message body
            this.MessageBodyStartIndex = index;
            if (this.contentLength > 0) {
                if (index + this.contentLength < packetEndIndex + 1)
                    throw new Exception("Incomplete SIP packet");
                else if (index + this.contentLength > packetEndIndex + 1)
                    base.PacketEndIndex = index + this.contentLength - 1;

                if (this.ContentType?.Equals("application/sdp", StringComparison.InvariantCultureIgnoreCase) == true) {
                    //TODO parse body as SDP if specified in the content-type
                    this.SDP = new SessionDescriptionProtocol(parentFrame.Data, index, this);
                }
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //throw new Exception("The method or operation is not implemented.");
            yield break;//no sub packets
        }

        internal class SessionDescriptionProtocol {
            //private Dictionary<char, string> fields;

            internal ushort? Port { get; }
            internal System.Net.IPAddress IP { get; }
            internal string Protocol { get; }

            internal SessionDescriptionProtocol(byte[] data, int index, AbstractPacket parentPacket) {
                //this.fields = new Dictionary<char, string>();
                string headerLine = "dummy value";


                while (index < parentPacket.PacketEndIndex) {
                    headerLine = Utils.ByteConverter.ReadLine(parentPacket.ParentFrame.Data, ref index, true);
                    if (headerLine.Contains("=")) {
                        string headerName = headerLine.Substring(0, headerLine.IndexOf('=')).Trim();
                        string headerValue = headerLine.Substring(headerLine.IndexOf('=') + 1).Trim();

                        if (headerName.Length == 1 && headerValue.Length > 0) {
                            //this.fields.Add(headerName[0], headerValue);

                            
                            if (headerName.Equals("c") && headerValue.StartsWith("IN", StringComparison.InvariantCultureIgnoreCase)) {
                                //c=IN IP4 224.2.17.12/127
                                //c=<nettype> <addrtype> <connection-address>
                                if (headerValue.Contains(" ")) {
                                    string[] parts = headerValue.Split(new[] { ' ' });
                                    if (parts.Length > 2 && System.Net.IPAddress.TryParse(parts[2].Trim(), out System.Net.IPAddress ip))
                                        this.IP = ip;
                                }
                            }
                            else if (headerName.Equals("m") && headerValue.StartsWith("audio", StringComparison.InvariantCultureIgnoreCase)) {
                                //Example: audio 10000 RTP/AVP 8 0 101
                                /*
                                 * 
                                 * m=<media> <port>/<number of ports> <proto> <fmt>
                                 * This field is used in the media description section to advertise properties of the media stream, such as the port it will be using for transmitting, the protocol used for streaming and the format or codec.
                                 *  <media> Used to specify media type, generally this can be audio, video, text etc.
                                 *  <port>  The port to which the media stream will be sent. Multiple ports can also be specified if more than 1 port is being used.
                                 *  <proto> The transport protocol used for streaming, e.g. RTP (real time protocol).
                                 *  <fmt>   The format of the media being sent, e.g. in which codec is the media encoded; e.g. PCMU, GSM etc.
                                 */
                                //string[] splitters = ;
                                if (headerValue.Contains(" ")) {
                                    string[] parts = headerValue.Split(new[] { ' ' });
                                    if(parts.Length > 1 && UInt16.TryParse(parts[1].Trim(), out ushort port))
                                        this.Port = port;
                                    if (parts.Length > 2)
                                        this.Protocol = parts[2].Trim();//typically "RTP/AVP"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
