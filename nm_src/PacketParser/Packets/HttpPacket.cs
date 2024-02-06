//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Packets {

    //http://en.wikipedia.org/wiki/Http
    //http://tools.ietf.org/html/rfc2616
    //http://tools.ietf.org/html/rfc2617 (HTTP Authentication)
    public class HttpPacket : AbstractPacket, ISessionPacket{
        public static readonly byte[] CHUNK_TRAILER = { 0x30, 0x0d, 0x0a, 0x0d, 0x0a };//see: RFC 2616 3.6.1 Chunked Transfer Coding

        //200818: Added WebDAV methods COPY, LOCK, MKCOL, MOVE, PROPFIND, PROPPATCH and UNLOCK
        public enum RequestMethods { GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS, CONNECT, COPY, LOCK, MKCOL, MOVE, PROPFIND, PROPPATCH, UNLOCK, none }
        internal enum ContentEncodings {
            Gzip,
            Compress,
            Deflate,
            Identity,//Identity is default
            Brotli,
            Base64//not part of RFC but added for flexibility
        }

        

        private readonly List<AbstractPacket> subPackets;

        //request variables
        private readonly RequestMethods requestMethod;//this one is "none" unless the message is a request message

        public string AcceptLanguage { get; set; } = null;
        public bool MessageTypeIsRequest { get; }
        public RequestMethods RequestMethod { get { return this.requestMethod; } }
        internal string RequestedHost { get; private set; }
        internal ushort? RequestedPort { get; private set; }
        public string RequestedFileName { get; }
        internal string UserAgentBanner { get; private set; }
        public string StatusCode { get; }
        public string StatusMessage { get; }
        public string ServerBanner { get; private set; }//server or reply web server. See: http://www.blackhat.com/presentations/bh-asia-02/bh-asia-02-grossman.pdf or http://www.blackhat.com/presentations/bh-usa-03/bh-us-03-shah/bh-us-03-shah.ppt
        public string ContentType { get; private set; }
        public long ContentLength { get; private set; }//defined in # bytes for "Content-Lenght" as in RFC2616
        public string ContentEncoding { get; private set; }//this could be for example GZIP, see: http://www.faqs.org/rfcs/rfc1952.html
        public string ContentDisposition { get; private set; }
        public string Cookie { get; private set; }
        public string TransferEncoding { get; private set; }//if encoding is "chunked" (such as for www.ripe.net) I will have to deal with: http://tools.ietf.org/html/rfc2616#section-3.6.1 Why can't people simply rely on TCP sequencing???
        public List<string> HeaderFields { get; }
        internal string WwwAuthenticateRealm { get; private set; }//Used to be WwwAuthenticateBasicRealm
        internal string AuthorizationCredentialsUsername { get; private set; }
        internal string AuthorizationCredentialsPassword { get; private set; }
        internal string ContentDispositionFilename { get; private set; }
        internal FileTransfer.ContentRange ContentRange { get; private set; }
        internal byte[] MessageBody { get; }

        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;

            //start testing
            int dataIndex = packetStartIndex;
            string startLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref dataIndex);

            if (startLine == null)
                return false;
            else if (startLine.Length > 2048)
                return false;
            else if (!Enum.IsDefined(typeof(RequestMethods), Utils.StringManglerUtil.GetFirstPart(startLine, ' ')?.ToUpper()) &&
                !(startLine.StartsWith("GET") || startLine.StartsWith("HEAD") || startLine.StartsWith("POST") || startLine.StartsWith("PUT") || startLine.StartsWith("DELETE") || startLine.StartsWith("TRACE") || startLine.StartsWith("OPTIONS") || startLine.StartsWith("CONNECT") || startLine.StartsWith("HTTP")))
                return false;

            try {
                result=new HttpPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                result=null;
            }


            if(result==null)
                return false;
            else
                return true;
        }

        private HttpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "HTTP") {
            /*
             * 
             *         generic-message = start-line
             *             *(message-header CRLF)
             *             CRLF
             *             [ message-body ]
             * 
             *         start-line      = Request-Line | Status-Line
             * 
             * */
            this.subPackets = new List<AbstractPacket>();
            this.HeaderFields = new List<string>();
            this.RequestedHost = null;
            this.RequestedFileName = null;
            this.UserAgentBanner = null;
            this.StatusCode = null;
            this.StatusMessage = null;
            this.ServerBanner = null;
            this.ContentType = null;
            this.ContentLength = -1;//instead of null
            this.ContentEncoding = null;
            this.Cookie = null;
            this.TransferEncoding = null;
            this.WwwAuthenticateRealm = null;
            this.AuthorizationCredentialsUsername = null;
            this.AuthorizationCredentialsPassword = null;
            this.PacketHeaderIsComplete = false;
            this.ContentDispositionFilename = null;
            this.ContentRange = null;

            int dataIndex = packetStartIndex;

            //a start-line
            string startLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref dataIndex);
            if (startLine == null)
                throw new Exception("HTTP packet does not contain a valid start line. Probably a false HTTP positive");
            if (startLine.Length > 2048)
                throw new Exception("HTTP start line is longer than 2048 bytes. Probably a false HTTP positive");

            if (dataIndex > packetEndIndex)
                throw new Exception("HTTP start line ends after packet end...");

            //if (Enum.TryParse<RequestMethods>(startLine.Split(' ').First()?.ToUpper(), out this.requestMethod)) {
            if (Enum.TryParse<RequestMethods>(Utils.StringManglerUtil.GetFirstPart(startLine, ' ')?.ToUpper(), out this.requestMethod)) {
                this.MessageTypeIsRequest = true;
            }
            else if (startLine.StartsWith("GET")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.GET;
            }
            else if (startLine.StartsWith("HEAD")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.HEAD;
            }
            else if (startLine.StartsWith("POST")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.POST;
            }
            else if (startLine.StartsWith("PUT")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.PUT;
            }
            else if (startLine.StartsWith("DELETE")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.DELETE;
            }
            else if (startLine.StartsWith("TRACE")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.TRACE;
            }
            else if (startLine.StartsWith("OPTIONS")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.OPTIONS;
            }
            else if (startLine.StartsWith("CONNECT")) {
                this.MessageTypeIsRequest = true;
                this.requestMethod = RequestMethods.CONNECT;
            }
            else if (startLine.StartsWith("HTTP")) {
                this.MessageTypeIsRequest = false;
                this.requestMethod = RequestMethods.none;
            }
            else
                throw new Exception("Incorrect HTTP Message Type or Request Method");
        
         
            //zero or more header fields (also known as "headers")
            while(true){
                string headerLine = Utils.ByteConverter.ReadLine(parentFrame.Data, ref dataIndex);
                if(headerLine==null)
                    break;//this.packetHeaderIsComplete will NOT be true!
                else if(headerLine.Length>0) {
                    this.HeaderFields.Add(headerLine);
                    this.ExtractHeaderField(headerLine);
                }
                else {//headerLine.Length==0
                    this.PacketHeaderIsComplete=true;//the header is complete and that's enough
                    break;//the for loop should stop now...
                }
            }

            //see if there is a message-body
            if(this.PacketHeaderIsComplete && this.MessageTypeIsRequest && (requestMethod == RequestMethods.HEAD || requestMethod == RequestMethods.GET)) {
                //this part is important in case there are chained (queued) requests as in HTTP 1.1
                this.MessageBody = null;
                this.PacketEndIndex = dataIndex - 1;
            }
            else if(this.PacketHeaderIsComplete && dataIndex<=packetEndIndex) {//we have a body!
                if (this.ContentLength > 0 && this.ContentLength < packetEndIndex - dataIndex + 1) {
                    this.MessageBody = new byte[this.ContentLength];
                    this.PacketEndIndex = (int)(dataIndex + this.ContentLength - 1);
                }
                else {
                    this.MessageBody = new byte[packetEndIndex - dataIndex + 1];
                }
                Array.Copy(parentFrame.Data, dataIndex, this.MessageBody, 0, this.MessageBody.Length);
            }
            else {
                this.MessageBody=null;
            }


            //now extract some interresting information from the packet
            if(this.MessageTypeIsRequest) {//REQUEST
                int requestUriOffset = this.requestMethod.ToString().Length + 1;
                string fileURI = startLine.Substring(requestUriOffset, startLine.Length - requestUriOffset);
                if(fileURI?.Contains(" HTTP") == true) {
                    fileURI=fileURI.Substring(0, fileURI.IndexOf(" HTTP"));
                }
                if(fileURI?.Length>0) {//If it is the index-file the URI will be just "/"
                    this.RequestedFileName=fileURI;
                }
                else
                    this.RequestedFileName=null;
            }
            else {//REPLY
                if(startLine.StartsWith("HTTP/1.")) {
                    this.StatusCode=startLine.Substring(9, 3);
                    if (startLine.Length > 12)
                        this.StatusMessage = startLine.Substring(12).Trim();
                }
            }
        }

        private void ExtractHeaderField(string headerField) {
            if (headerField.StartsWith("Host: ")) {//look for the host
                this.RequestedHost = headerField.Substring(6).Trim();
                if(this.RequestedHost?.Contains(':') == true) {
                    string[] hostAndPort = this.RequestedHost.Split(':');
                    if (UInt16.TryParse(hostAndPort[1], out ushort port)) {
                        this.RequestedPort = port;
                        this.RequestedHost = hostAndPort[0];
                    }
                }
                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("Requested Host", headerField.Substring(6).Trim());
            }
            else if (headerField.StartsWith("User-Agent: ", StringComparison.OrdinalIgnoreCase)) {
                this.UserAgentBanner = headerField.Substring(12).Trim();
                if (!this.ParentFrame.QuickParse)
                    base.Attributes.Add("User-Agent", this.UserAgentBanner = headerField.Substring(12).Trim());
            }
            else if (headerField.StartsWith("Server: ", StringComparison.OrdinalIgnoreCase)) {
                this.ServerBanner = headerField.Substring(8).Trim();
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Server banner", this.ServerBanner = headerField.Substring(8).Trim());
            }
            else if (headerField.StartsWith("Cookie: ", StringComparison.OrdinalIgnoreCase)) {
                //http://www.w3.org/Protocols/rfc2109/rfc2109
                this.Cookie = headerField.Substring(8).Trim();
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Cookie", this.Cookie);
            }
            else if (headerField.StartsWith("Set-Cookie: ", StringComparison.OrdinalIgnoreCase)) {
                if (String.IsNullOrEmpty(this.Cookie))
                    this.Cookie = headerField.Substring(12).Trim();
                else
                    this.Cookie += "; " + headerField.Substring(12).Trim();
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Cookie", this.Cookie);
            }
            else if (headerField.StartsWith("Content-Type: ", StringComparison.OrdinalIgnoreCase))
                this.ContentType = headerField.Substring(14).Trim();
            else if (headerField.StartsWith("Content-Length: ", StringComparison.OrdinalIgnoreCase))
                this.ContentLength = Convert.ToInt64(headerField.Substring(16).Trim());
            else if (headerField.StartsWith("Content-Encoding: ", StringComparison.OrdinalIgnoreCase))
                this.ContentEncoding = headerField.Substring(18).Trim();
            else if (headerField.StartsWith("Transfer-Encoding: ", StringComparison.OrdinalIgnoreCase))
                this.TransferEncoding = headerField.Substring(19).Trim();
            else if (headerField.StartsWith("WWW-Authenticate: ", StringComparison.OrdinalIgnoreCase) && headerField.Contains("realm=\"")) {
                int realmStart = headerField.IndexOf("realm=\"") + 7;
                int realmEnd = headerField.IndexOf('\"', realmStart);
                if (realmStart >= 0 && realmEnd > 0)
                    this.WwwAuthenticateRealm = headerField.Substring(realmStart, realmEnd - realmStart).Trim();
            }
            else if(headerField.StartsWith("WWW-Authenticate: Negotiate ", StringComparison.InvariantCultureIgnoreCase)) {
                try {
                    string base64 = headerField.Substring("WWW-Authenticate: Negotiate ".Length).Trim();
                    byte[] gssApiData = Convert.FromBase64String(base64);
                    //create a "fake" frame
                    Frame virtualAuthFrame = new Frame(this.ParentFrame.Timestamp, gssApiData, this.ParentFrame.FrameNumber);
                    SmbPacket.SecurityBlob securityBlob = new SmbPacket.SecurityBlob(virtualAuthFrame, 0, virtualAuthFrame.Data.Length - 1);
                    this.subPackets.Add(securityBlob);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error parsing HTTP \"WWW-Authenticate: Negotiate\" in " + this.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                    if (!this.ParentFrame.QuickParse)
                        this.ParentFrame.Errors.Add(new Frame.Error(this.ParentFrame, PacketStartIndex, this.PacketEndIndex, "Cannot parse credentials in HTTP Authorization: Negotiate (" + e.Message + ")"));
                }
            }
            else if (headerField.StartsWith("Proxy-Authenticate: Basic realm=", StringComparison.OrdinalIgnoreCase))
                this.WwwAuthenticateRealm = headerField.Substring(33, headerField.Length - 34).Trim();
            else if (headerField.StartsWith("Authorization: Basic ", StringComparison.OrdinalIgnoreCase)) {
                try {
                    string base64string = headerField.Substring(21).Trim();
                    Byte[] bArray = Convert.FromBase64String(base64string);
                    StringBuilder sb = new StringBuilder(bArray.Length);
                    foreach (byte b in bArray)
                        sb.Append((char)b);
                    string s = sb.ToString();
                    if (s.Contains(":")) {
                        this.AuthorizationCredentialsUsername = s.Substring(0, s.IndexOf(':'));
                        if (s.IndexOf(':') + 1 < s.Length)
                            this.AuthorizationCredentialsPassword = s.Substring(s.IndexOf(':') + 1);
                        else
                            this.AuthorizationCredentialsPassword = "";
                    }
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error parsing HTTP \"Authorization: Basic\" in " + this.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                    if (!this.ParentFrame.QuickParse)
                        this.ParentFrame.Errors.Add(new Frame.Error(this.ParentFrame, PacketStartIndex, this.PacketEndIndex, "Cannot parse credentials in HTTP Authorization (" + e.Message + ")"));
                }
            }
            else if (headerField.StartsWith("Authorization: Digest ", StringComparison.OrdinalIgnoreCase)) {
                try {
                    string authorizationString = headerField.Substring(22).Trim();
                    foreach (string keyValueString in authorizationString.Split(new char[] { ',' })) {
                        string[] parts = keyValueString.Split(new char[] { '=' });
                        if (parts.Length == 2) {
                            string name = parts[0].Trim();
                            string value = parts[1].Trim(new char[] { ' ', '\"', '\'' });
                            if (name.Equals("username", StringComparison.InvariantCultureIgnoreCase)) {
                                this.AuthorizationCredentialsUsername = value;
                                if (this.AuthorizationCredentialsPassword == null)
                                    this.AuthorizationCredentialsPassword = "N/A";
                            }
                            else if (name.Equals("realm", StringComparison.InvariantCultureIgnoreCase))
                                this.WwwAuthenticateRealm = value;
                        }
                    }
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error parsing HTTP \"Authorization: Digest\" in " + this.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                    if (!this.ParentFrame.QuickParse)
                        this.ParentFrame.Errors.Add(new Frame.Error(this.ParentFrame, PacketStartIndex, this.PacketEndIndex, "Cannot parse credentials in HTTP Authorization (" + e.Message + ")"));
                }
            }
            else if (headerField.StartsWith("Authorization: Negotiate", StringComparison.InvariantCultureIgnoreCase)) {
                try { 
                    string base64 = headerField.Substring("Authorization: Negotiate".Length).Trim();
                    byte[] gssApiData = Convert.FromBase64String(base64);
                    //create a "fake" frame
                    Frame virtualAuthFrame = new Frame(this.ParentFrame.Timestamp, gssApiData, this.ParentFrame.FrameNumber);
                    SmbPacket.SecurityBlob securityBlob = new SmbPacket.SecurityBlob(virtualAuthFrame, 0, virtualAuthFrame.Data.Length - 1);
                    this.subPackets.Add(securityBlob);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error parsing HTTP \"Authorization: Negotiate\" in " + this.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                    if (!this.ParentFrame.QuickParse)
                        this.ParentFrame.Errors.Add(new Frame.Error(this.ParentFrame, PacketStartIndex, this.PacketEndIndex, "Cannot parse credentials in HTTP Authorization: Negotiate (" + e.Message + ")"));
                }
            }
            else if (headerField.StartsWith("Content-Disposition:", StringComparison.OrdinalIgnoreCase)) {
                this.ContentDisposition = headerField.Substring(20).Trim();
                if (headerField.Contains("filename=")) {
                    string filename = headerField.Substring(headerField.IndexOf("filename=") + 9);
                    filename = filename.Trim();
                    if (filename.StartsWith("\"") && filename.IndexOf('\"', 1) > 0)//get the string inside the quotations
                        filename = filename.Substring(1, filename.IndexOf('\"', 1) - 1);
                    if (filename.Length > 0)
                        this.ContentDispositionFilename = filename;
                }
                else if (headerField.Contains("filename*=")) {
                    //Example: Content-Disposition: inline; filename*=UTF-8''944.png
                    //rfc6266 specifies that filename-parm can be "filename*" "=" ext-value
                    //rfc5987 sprcifies that ext-value = charset  "'" [ language ] "'" value-chars
                    int charsetIndex = headerField.IndexOf("filename*=") + 10;
                    int quoteIndex = headerField.IndexOf('\'', charsetIndex);
                    if (charsetIndex > 0 && quoteIndex > 0) {
                        string charset = headerField.Substring(charsetIndex, quoteIndex - charsetIndex);
                        if (charset != null && charset.Length > 0) {
                            try {
                                Encoding encoding = System.Text.Encoding.GetEncoding(charset);
                                int extValueIndex = headerField.IndexOf('\'', quoteIndex + 1) + 1;
                                byte[] extValueBytes = System.Text.Encoding.Default.GetBytes(headerField.Substring(extValueIndex));
                                string filename = encoding.GetString(extValueBytes);
                                filename = filename.Trim();
                                if (filename.StartsWith("\"") && filename.IndexOf('\"', 1) > 0)//get the string inside the quotations
                                    filename = filename.Substring(1, filename.IndexOf('\"', 1) - 1);
                                if (filename.Length > 0)
                                    this.ContentDispositionFilename = filename;
                            }
                            catch (Exception e) {
                                SharedUtils.Logger.Log("Error parsing file name with charset \"" + charset + "\" in " + this.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Warning);
                            }
                        }
                    }
                }
            }
            else if (headerField.StartsWith("Content-Range: ", StringComparison.OrdinalIgnoreCase)) {
                //Content-Range: bytes 8621-23239/42941008
                //Content-Range: bytes 21010-47021/47022
                System.Text.RegularExpressions.Regex rangeRegEx = new System.Text.RegularExpressions.Regex(@"bytes (?<start>[0-9]+)-(?<end>[0-9]+)/(?<total>[0-9]+)$");
                System.Text.RegularExpressions.Match rangeMatch = rangeRegEx.Match(headerField);
                if (rangeMatch.Success) {
                    long start, end, total;
                    if (Int64.TryParse(rangeMatch.Groups["start"].Value, out start) && Int64.TryParse(rangeMatch.Groups["end"].Value, out end) && Int64.TryParse(rangeMatch.Groups["total"].Value, out total)) {
                        this.ContentRange = new FileTransfer.ContentRange() { Start = start, End = end, Total = total };
                    }
                }
            }
            else if(headerField.StartsWith("Accept-Language: ", StringComparison.OrdinalIgnoreCase)) {
                this.AcceptLanguage = headerField.Substring(17).Trim();

            }
        }

        internal static IEnumerable<(string name, string value)> GetUrlEncodedParts(string urlEncodedData, bool isFormPostData) {
            char[] separator1 = { '&' };
            char[] separator2 = { '=' };
            string data = System.Web.HttpUtility.UrlDecode(urlEncodedData);
            ICollection<string> formNameValues = data.Split(separator1);
            if (isFormPostData) {
                List<string> mergedNameValues = new List<string>();
                bool lastValueCompleted = true;
                foreach (string formNameValue in formNameValues) {
                    if (lastValueCompleted) {
                        mergedNameValues.Add(formNameValue);
                        if (formNameValue.Contains("=[{") && !formNameValue.EndsWith("}]"))
                            lastValueCompleted = false;//we need to read until the end bracket before splitting again
                    }
                    else {
                        //rebuild the split data
                        mergedNameValues[mergedNameValues.Count - 1] = mergedNameValues[mergedNameValues.Count - 1] + separator1 + formNameValue;
                        if (formNameValue.EndsWith("}]"))
                            lastValueCompleted = true;
                    }
                }
                formNameValues = mergedNameValues;
            }
            foreach (string formNameValue in formNameValues) {
                if (formNameValue.Length > 0) {
                    int eqIndex = formNameValue.IndexOf('=');
                    if (eqIndex > 0 && eqIndex < formNameValue.Length - 1) {
                        string controlName = System.Web.HttpUtility.UrlDecode(formNameValue.Substring(0, eqIndex));
                        string formValue = System.Web.HttpUtility.UrlDecode(formNameValue.Substring(eqIndex + 1));

                        yield return (controlName, formValue);
                    }
                }
            }
        }

        internal static System.Collections.Specialized.NameValueCollection GetUrlEncodedNameValueCollection(string urlEncodedData, bool isFormPostData) {
            System.Collections.Specialized.NameValueCollection returnCollection=new System.Collections.Specialized.NameValueCollection();
            foreach((string controlName, string formValue) in GetUrlEncodedParts(urlEncodedData, isFormPostData)) {
                returnCollection.Add(controlName, formValue);
            }
            return returnCollection;
        }

        /// <summary>
        /// Returns the names and values of the parameters (variables) passed in the querystring
        /// </summary>
        /// <returns></returns>
        internal System.Collections.Specialized.NameValueCollection GetQuerystringData() {
            if(RequestedFileName!=null && RequestedFileName.Contains("?")) {
                return GetUrlEncodedNameValueCollection(RequestedFileName.Substring(RequestedFileName.IndexOf('?')+1), false);
            }
            else
                return null;
        }

        //http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4
        //internal System.Collections.Specialized.NameValueCollection GetFormData() {
        internal System.Collections.Generic.List<Mime.MultipartPart> GetFormData() {
            System.Collections.Generic.List<Mime.MultipartPart> returnMultiPartData=new List<Mime.MultipartPart>();

            if(this.RequestMethod!=RequestMethods.POST || this.MessageBody==null || this.MessageBody.Length<=0 || this.ContentType==null)
                return returnMultiPartData;
            else if(this.ContentType.ToLower(System.Globalization.CultureInfo.InvariantCulture).StartsWith("application/x-www-form-urlencoded")) {
                Mime.MultipartPart mimeMultipart = new Mime.MultipartPart(GetUrlEncodedNameValueCollection(Utils.ByteConverter.ReadString(this.MessageBody), true));

                returnMultiPartData.Add(mimeMultipart);
                return returnMultiPartData;
            }
            else if(this.ContentType.ToLower(System.Globalization.CultureInfo.InvariantCulture).StartsWith("multipart/form-data")) {
                //http://www.ietf.org/rfc/rfc2388.txt
                //http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4
                //wireshark: \epan\dissectors\packet-multipart.c
                //The content "multipart/form-data" follows the rules of all multipart MIME data streams as outlined in [RFC2045]. 
                //see if there is a boundary in the Content-Type definition

                string contentTypeEnding=ContentType.Substring(21);
                if(contentTypeEnding.StartsWith("boundary=")) {
                    string boundary=contentTypeEnding.Substring(9);
                    foreach(Mime.MultipartPart part in Mime.PartBuilder.GetParts(this.MessageBody, boundary))
                        returnMultiPartData.Add(part);
                    return returnMultiPartData;
                    

                }

            }
            return null;//we failed to get the data
        }

        internal bool ContentIsComplete() {
            if(this.ContentLength==0)
                return true;
            if(this.MessageBody==null)
                return false;
            return this.MessageBody.Length>=this.ContentLength;
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if (this.subPackets.Count == 0) {
                //Do nothing, no known sub packets... well or can I define HTTP data chunks as a sub packet?
                yield break;
            }
            else {
                foreach (AbstractPacket p in this.subPackets) {
                    yield return p;
                    foreach (AbstractPacket subPacket in p.GetSubPackets(false))
                        yield return subPacket;
                }
            }
        }

        #region ISessionPacket Members

        public bool PacketHeaderIsComplete { get; }

        public int ParsedBytesCount { get { return base.PacketLength; } }

        #endregion

        

    }
}
