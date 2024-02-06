//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketParser.Packets;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using static PacketParser.FileTransfer.FileStreamAssembler;

namespace PacketParser.PacketHandlers {
    public class HttpPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public static System.Collections.Specialized.NameValueCollection ParseHeaders(Packets.HttpPacket httpPacket, SortedList<string, string> ignoredHeaderNames = null) {
            System.Collections.Specialized.NameValueCollection httpHeaders = new System.Collections.Specialized.NameValueCollection();
            foreach (string header in httpPacket.HeaderFields) {
                int delimiterIndex = header.IndexOf(':');
                if (delimiterIndex > 0 && delimiterIndex < header.Length) {
                    string headerName = header.Substring(0, delimiterIndex).Trim();
                    //if (!httpHeaders.ContainsKey(headerName))
                    if (ignoredHeaderNames == null || !ignoredHeaderNames.ContainsKey(headerName.ToLower()))
                        httpHeaders.Add(headerName, header.Substring(delimiterIndex + 1).Trim());
                }
            }
            return httpHeaders;
        }


        private readonly Dictionary<byte, string> UriChecksum8Fingerprints = new Dictionary<byte, string> {
            { 92, "CobaltStrike or Meterpreter URI" },//Windows
            { 93, "CobaltStrike x64 URI" }/*,//Windows x64
            { 80, "Python" },
            { 88, "Java" },
            { 98, "Existing session" },
            { 95, "Stageless session" }*/
        };

        //extensions that should always be replaced to avoid mime-type file extensions
        internal static readonly Dictionary<string, string> ExtensionReplacements = new Dictionary<string, string> {
            { "vnd.ms-cab-compressed", "cab" },
            { "x-icon", "ico" },
            { "java-archive", "jar" },
            { "x-javascript", "js" },
            { "javascript", "js" },
            { "vnd.wap.mms-message", "mms" },
            { "MP2T", "mpeg" },
            { "svg+xml", "svg" },
            { "x-shockwave-flash", "swf" },
            { "soap xml", "xml" },
            { "soap+xml", "xml" }
        };

        //extensions that should be left untouched if the mime-type matches
        internal static readonly ReadOnlyCollection<(string extension, string mimeType)> ExtensionMimeTypeCombos = new List<(string extension, string mimeType)> {
            (".asc", "pgp-keys"),
            (".bat", "x-msdos-program"),
            (".cab", "octet-stream"),
            (".cab", "vnd.ms-cab-compressed"),
            (".crl", "pkix-crl"),
            (".crl", "octet-stream"),
            (".crt", "x-x509-ca-cert"),
            (".crx", "x-chrome-extension"),
            (".deb", "octet-stream"),
            (".deb", "x-debian-package"),
            (".dll", "octet-stream"),
            (".dll", "x-msdownload"),
            (".doc", "msword"),
            (".docx", "vnd.openxmlformats-officedocument.wordprocessingml.document"),
            (".exe", "octet-stream"),
            (".exe", "x-msdos-program"),
            (".exe", "x-msdownload"),
            (".gz", "x-gzip"),
            (".htm", "html"),
            (".ico", "x-icon"),
            (".ico", Utils.StringManglerUtil.PLAIN_CONTENT_TYPE_EXTENSION),
            (".jar", "java-archive"),
            (".jpg", "jpeg"),
            (".js", "x-javascript"),
            (".js", "javascript"),
            (".mms", "vnd.wap.mms-message"),
            (".png", "octet-stream"),//sites like SoundCloud's CDN (sndcdn.com) send images as content-type "octet-stream"
            (".svg", "svg+xml"),
            (".swf", "x-shockwave-flash"),
            (".tgz", "x-gzip"),
            (".vbs", "vbscript"),
            (".xls", "vnd.ms-excel"),
            (".xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            ( ".xml", "soap xml" ),
            ( ".xml", "soap+xml" ),

            //https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types

            (".aac", "aac"),
            (".abw", "x-abiword"),
            (".arc", "x-freearc"),
            (".avi", "x-msvideo"),
            (".azw", "vnd.amazon.ebook"),
            (".bin", "octet-stream"),
            (".bz ", "x-bzip"),
            (".bz2", "x-bzip2"),
            (".class", "java-vm"),
            (".csh", "x-csh"),
            (".doc", "msword"),
            (".docx", "vnd.openxmlformats-officedocument.wordprocessingml.document"),
            (".eot", "vnd.ms-fontobject"),
            (".epub", "epub+zip"),
            (".gz", "gzip"),
            (".gif", "gif"),
            (".ico", "vnd.microsoft.icon"),
            (".ics", "calendar"),
            (".jar", "java-archive"),
            (".jpg", "jpeg"),
            (".js", "javascript"),
            (".json", "json"),
            (".jsonld", "ld+json"),
            (".mid", "midi"),
            (".mid", "x-midi"),
            (".midi", "midi"),
            (".midi", "x-midi"),
            (".mjs", "javascript"),
            (".mp3", "mpeg"),
            (".mpeg", "mpeg"),
            (".mpkg", "vnd.apple.installer+xml"),
            (".odp", "vnd.oasis.opendocument.presentation"),
            (".ods", "vnd.oasis.opendocument.spreadsheet"),
            (".odt", "vnd.oasis.opendocument.text"),
            (".oga", "ogg"),
            (".ogv", "ogg"),
            (".ogx", "ogg"),
            (".opus", "opus"),
            (".otf", "otf"),
            (".png", "png"),
            (".pdf", "pdf"),
            (".php", "php"),
            (".ppt", "vnd.ms-powerpoint"),
            (".pptx", "vnd.openxmlformats-officedocument.presentationml.presentation"),
            (".rar", "x-rar-compressed"),
            (".rtf", "rtf"),
            (".sh", "x-sh"),
            (".svg", "svg+xml"),
            (".swf", "x-shockwave-flash"),
            (".tar", "x-tar"),
            (".ts", "mp2t"),
            (".ttf", "ttf"),
            (".txt", "plain"),
            (".vsd", "vnd.visio"),
            (".wav", "wav"),
            (".weba", "webm"),
            (".webm", "webm"),
            (".webp", "webp"),
            (".woff", "woff"),
            (".woff2", "woff2"),
            (".xhtml", "xhtml+xml"),
            (".xls", "vnd.ms-excel"),
            (".xlsx", "vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            //(".xml", "xml if not readable from casual users (RFC 3023, section 3) text/xml if readable from casual users (RFC 3023, section 3)"),
            (".xul", "vnd.mozilla.xul+xml"),
            //(".zip", "zip"),
            (".3gp", "3gpp"),
            (".3gp", "3gpp"),
            (".3g2", "3gpp2"),
            (".7z", "x-7z-compressed")

        }.AsReadOnly();

        internal static readonly HashSet<string> BoringXHeaders = new HashSet<string> {
            
            "x-amz-replication-status",
            "x-amz-storage-class",
            "x-amz-server-side-encryption",
            "x-amz-version-id",
            "x-amz-cf-id",
            "X-Amz-Cf-Id",
            "x-cache",
            "x-content-type-options",
            "x-response-time",
            "x-transaction",
            "x-tsa-request-body-time",
            "x-cache-hits",
            "x-connection-hash",
            "x-nc",
            "x-timer"
         };

        public static bool TryGetUriChecksum(string uri, out byte checksum8) {
            checksum8 = 0;
            uri = uri?.Trim('/');
            uri = uri?.Split('/').LastOrDefault();
            if (string.IsNullOrEmpty(uri))
                return false;
            //https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/payloads/meterpreter/uri_checksum.rb
            //Ignore non-base64url characters in the URL
            //uri_bare = uri.gsub(/[^a-zA-Z0-9_\-]/, '')
            var nonB64Regex = new System.Text.RegularExpressions.Regex(@"[^a-zA-Z0-9_\-]");
            string uriBare = nonB64Regex.Replace(uri, string.Empty);
            if(uriBare ==null || uriBare.Length < 4 || uriBare.Length > 28) //https://www.bussink.net/metasploit-valid-url-checksum8/
                return false;
            //Hash checksum8 is the sum of all bytes inside the file, interpreted as unsigned, 8-bit integers.
            int sum = 0;
            foreach(char c in uriBare) {
                sum += (sbyte)c;
            }
            checksum8 = (byte)sum;
            return true;
        }
        internal static bool ExtensionMimeTypeCombosMatches(string filename, string mimeExtension = null) {
            foreach ((string extension, string mimeType) in ExtensionMimeTypeCombos) {
                if (filename.EndsWith(extension, StringComparison.InvariantCultureIgnoreCase) && (mimeExtension == null || mimeType.Equals(mimeExtension, StringComparison.InvariantCultureIgnoreCase))) {
                    return true;
                }
            }
            return false;
        }

        internal static string AppendMimeContentTypeAsExtension(string filename, string contentType) {
            if (contentType != null && contentType.Contains("/") && contentType.IndexOf('/') < contentType.Length - 1) {
                string mimeExtension = Utils.StringManglerUtil.GetExtension(contentType);


                if (mimeExtension?.Length > 0 &&
                    !filename.EndsWith("." + mimeExtension, StringComparison.InvariantCultureIgnoreCase) &&
                    !(mimeExtension.Length > 2 &&
                      mimeExtension.StartsWith("x-", StringComparison.InvariantCultureIgnoreCase) &&
                      filename.EndsWith("." + mimeExtension.Substring(2)))
                    ) {
                    //string assemblerExtension = Utils.StringManglerUtil.GetExtension(assembler.Filename);
                    if (ExtensionMimeTypeCombosMatches(filename, mimeExtension))
                        mimeExtension = null;


                    if (mimeExtension != null) {//append the content type as extension
                        if (ExtensionReplacements.ContainsKey(mimeExtension))
                            filename = filename + "." + ExtensionReplacements[mimeExtension];
                        else if(mimeExtension.Length > 2 && mimeExtension.StartsWith("x-", StringComparison.InvariantCultureIgnoreCase)) {
                            filename = filename + "." + mimeExtension.Substring(2).Trim();
                        }
                        else
                            filename = filename + "." + mimeExtension;
                    }
                }
            }
            return filename;
        }

        internal static (string filename, string fileLocation) GetFilenameAndLocation(string fileUri) {

            string queryString = null;
            if (fileUri.Contains("?")) {
                if (fileUri.IndexOf('?') + 1 < fileUri.Length)
                    queryString = fileUri.Substring(fileUri.IndexOf('?') + 1);
                fileUri = fileUri.Substring(0, fileUri.IndexOf('?'));
            }
            if (fileUri.StartsWith("http://"))
                fileUri = fileUri.Substring(7);
            if (fileUri.StartsWith("www.") && fileUri.Contains("/"))
                fileUri = fileUri.Substring(fileUri.IndexOf("/"));

            //char[] separators={ '/' };
            char[] separators = new char[System.IO.Path.GetInvalidPathChars().Length + 1];
            Array.Copy(System.IO.Path.GetInvalidPathChars(), separators, System.IO.Path.GetInvalidPathChars().Length);
            separators[separators.Length - 1] = '/';

            string[] uriParts = fileUri.Split(separators);
            string filename;
            string fileLocation = "";

            if (fileUri.EndsWith("/")) {
                filename = "index";//"filename = "index.html";
                for (int i = 0; i < uriParts.Length; i++)
                    if (uriParts[i].Length > 0 && !uriParts[i].Contains(".."))
                        fileLocation += "/" + uriParts[i];
            }
            else {
                filename = uriParts[uriParts.Length - 1];
                for (int i = 0; i < uriParts.Length - 1; i++)
                    if (uriParts[i].Length > 0 && !uriParts[i].Contains(".."))
                        fileLocation += "/" + uriParts[i];
            }

            //make sure all queryString-depending dynamic webpages are shown individually
            if (queryString != null && queryString.Length > 0 && !ExtensionMimeTypeCombosMatches(filename))
                filename += "." + queryString.GetHashCode().ToString("X4");
            return (filename, fileLocation);
        }

        internal static IEnumerable<(string name, string value)> GetCookieParts(string cookie) {
            char[] separators = { ';', ',' };
            foreach (string s in cookie.Split(separators)) {
                string cookieFragment = s.Trim();
                int splitOffset = cookieFragment.IndexOf('=');
                if (splitOffset > 0)
                    yield return (cookieFragment.Substring(0, splitOffset), cookieFragment.Substring(splitOffset + 1));
                else
                    yield return (cookieFragment, "");
            }
        }

        private PopularityList<FiveTuple, KeyValuePair<string, ushort>> httpConnectIpPorts;
        public override Type[] ParsedTypes { get; } = { typeof(Packets.HttpPacket) };

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.HTTP; }
        }

        public HttpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.httpConnectIpPorts = new PopularityList<FiveTuple, KeyValuePair<string, ushort>>(64);
        }

        #region ITcpSessionPacketHandler Members

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {

            bool successfulExtraction =false;

            Packets.HttpPacket httpPacket=null;
            Packets.TcpPacket tcpPacket=null;
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.HttpPacket))
                    httpPacket=(Packets.HttpPacket)p;
                else if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
            }

            if(httpPacket!=null && tcpPacket!=null){
                if(httpPacket.PacketHeaderIsComplete) {
                    //check if it is a POST and content length is small
                    if(httpPacket.RequestMethod!=Packets.HttpPacket.RequestMethods.POST || httpPacket.ContentLength>4096/* used to be 1024*/ || httpPacket.ContentIsComplete()) {
                        successfulExtraction = this.ExtractHttpData(tcpSession, httpPacket, tcpPacket, tcpSession.Flow.FiveTuple, transferIsClientToServer, base.MainPacketHandler);
                        //successfulExtraction=true;
                    }

                    if (base.MainPacketHandler.ExtraHttpPacketHandler != null)
                        base.MainPacketHandler.ExtraHttpPacketHandler.ExtractHttpData(httpPacket, tcpPacket, tcpSession.Flow.FiveTuple, transferIsClientToServer, base.MainPacketHandler);
                }

            }
            if(successfulExtraction) {
                
                return httpPacket.PacketLength;
            }
                
            else
                return 0;
        }

        public void Reset() {
            this.httpConnectIpPorts.Clear();
        }

        

        /// <summary>
        /// 
        /// </summary>
        /// <param name="httpPacket"></param>
        /// <param name="tcpPacket"></param>
        /// <param name="sourceHost"></param>
        /// <param name="destinationHost"></param>
        /// <param name="mainPacketHandler"></param>
        /// <returns>True if the data was successfully parsed. False if the data need to be parsed again with more data</returns>
        private bool ExtractHttpData(NetworkTcpSession tcpSession, Packets.HttpPacket httpPacket, Packets.TcpPacket tcpPacket, FiveTuple fiveTuple, bool transferIsClientToServer, PacketHandler mainPacketHandler) {
            
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = fiveTuple.ClientHost;
                destinationHost = fiveTuple.ServerHost;
            }
            else {
                sourceHost = fiveTuple.ServerHost;
                destinationHost = fiveTuple.ClientHost;
            }

            //A HTTP cookie can be set by both client and server
            System.Collections.Specialized.NameValueCollection cookieParams = null;
            if (httpPacket.Cookie != null) {
                cookieParams = new System.Collections.Specialized.NameValueCollection();

                foreach((string name, string value) in GetCookieParts(httpPacket.Cookie)) {
                    cookieParams.Add(name, value);
                    //special handling of IcedID cookies
                    //https://unit42.paloaltonetworks.com/wireshark-quiz-icedid-answers/
                    if (name == "_u" && value.Contains(':')) {
                        try {
                            string hostnameHex = value.Split(':')[0];
                        
                            byte[] hostnameBytes = Utils.ByteConverter.ToByteArrayFromHexString("0x" + hostnameHex);
                            string hostname = ASCIIEncoding.ASCII.GetString(hostnameBytes);
                            sourceHost.AddHostName(hostname, "IcedID _u cookie");

                            string usernameHex = value.Split(':')[1];
                            byte[] usernameBytes = Utils.ByteConverter.ToByteArrayFromHexString("0x" + usernameHex);
                            string username = ASCIIEncoding.ASCII.GetString(usernameBytes);
                            sourceHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.User, username);
                            
                        }
                        catch { }
                    }
                    else if(name == "__io" && value.Contains('_')) {
                        string sid = value.Replace('_', '-');
                        sourceHost.AddNumberedExtraDetail("SID", sid);
                    }
                    else if(name == "_gat" && value.Contains('.')) {
                        sourceHost.AddNumberedExtraDetail("Windows version", value);
                    }
                }
                NetworkHost client, server;
                if(httpPacket.MessageTypeIsRequest) {
                    client = sourceHost;
                    server = destinationHost;
                }
                else {
                    client = destinationHost;
                    server = sourceHost;
                }
                NetworkCredential inCookieCredential = NetworkCredential.GetNetworkCredential(cookieParams, client, server, "HTTP Cookie parameter", httpPacket.ParentFrame.Timestamp);
                if (inCookieCredential != null)
                    mainPacketHandler.AddCredential(inCookieCredential);
                if(httpPacket.RequestedHost?.Length > 0)
                    mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, cookieParams, httpPacket.ParentFrame.Timestamp, "HTTP Cookie for " + httpPacket.RequestedHost));
                else
                    mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, cookieParams, httpPacket.ParentFrame.Timestamp, "HTTP Cookie"));

                NetworkCredential credential = new NetworkCredential(client, server, "HTTP Cookie", httpPacket.Cookie, "N/A", httpPacket.ParentFrame.Timestamp, httpPacket.RequestedHost);
                mainPacketHandler.AddCredential(credential);
            }

            if (httpPacket.MessageTypeIsRequest) {
                //HTTP request
                {
                    System.Collections.Specialized.NameValueCollection httpRequestNvc = new System.Collections.Specialized.NameValueCollection();
                    httpRequestNvc.Add(httpPacket.RequestMethod.ToString(), httpPacket.RequestedFileName);
                    if (httpPacket.RequestedHost?.Length > 0)
                        base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(httpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, httpRequestNvc, httpPacket.ParentFrame.Timestamp, "HTTP Request to " + httpPacket.RequestedHost));
                    else
                        base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(httpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, httpRequestNvc, httpPacket.ParentFrame.Timestamp, "HTTP Request"));
                    //base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(httpPacket.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, httpRequestNvc, httpPacket.ParentFrame.Timestamp, "HTTP Request"));

                }

                if (TryGetUriChecksum(httpPacket.RequestedFileName, out byte checksum8) && this.UriChecksum8Fingerprints.ContainsKey(checksum8)) {
                    /**
                     * URI_CHECKSUM_INITW      = 92 # Windows
                     * URI_CHECKSUM_INITN      = 92 # Native (same as Windows)
                     * URI_CHECKSUM_INITP      = 80 # Python
                     * URI_CHECKSUM_INITJ      = 88 # Java
                     * URI_CHECKSUM_CONN       = 98 # Existing session
                     * URI_CHECKSUM_INIT_CONN  = 95 # New stageless session
                     **/
                    string parmName = this.UriChecksum8Fingerprints[checksum8];
                    destinationHost.AddNumberedExtraDetail(parmName, httpPacket.RequestedFileName);
                    if (httpPacket.RequestedHost != null)
                        sourceHost.AddNumberedExtraDetail(parmName, httpPacket.RequestedHost + httpPacket.RequestedFileName);
                }


                if (httpPacket.UserAgentBanner != null && httpPacket.UserAgentBanner.Length > 0)
                    sourceHost.AddHttpUserAgentBanner(httpPacket.UserAgentBanner);
                if (httpPacket.RequestedHost != null && httpPacket.RequestedHost.Length > 0)
                    destinationHost.AddHostName(httpPacket.RequestedHost, httpPacket.PacketTypeDescription);

                if (httpPacket.AuthorizationCredentialsUsername != null) {
                    NetworkCredential nc = new NetworkCredential(sourceHost, destinationHost, httpPacket.PacketTypeDescription, httpPacket.AuthorizationCredentialsUsername, httpPacket.AuthorizationCredentialsPassword, httpPacket.ParentFrame.Timestamp);
                    mainPacketHandler.AddCredential(nc);
                    //this.AddCredential(nc);
                }
                if(httpPacket.AcceptLanguage?.Length > 0) {
                    sourceHost.AddNumberedExtraDetail("Accept-Language", httpPacket.AcceptLanguage);
                }
                if (httpPacket.HeaderFields != null && httpPacket.HeaderFields.Count > 0) {
                    SortedList<string, string> ignoredHeaderNames = new SortedList<string, string>();
                    ignoredHeaderNames.Add("accept", null);
                    ignoredHeaderNames.Add("connection", null);
                    ignoredHeaderNames.Add("accept-language", null);
                    ignoredHeaderNames.Add("accept-encoding", null);


                    this.ExtractHeaders(httpPacket, fiveTuple, transferIsClientToServer, sourceHost, destinationHost, ignoredHeaderNames);



                }


                //file transfer
                if ((httpPacket.RequestMethod == Packets.HttpPacket.RequestMethods.GET || httpPacket.RequestMethod == Packets.HttpPacket.RequestMethods.POST || httpPacket.RequestMethod == Packets.HttpPacket.RequestMethods.PUT) && httpPacket.RequestedFileName != null) {

                    System.Collections.Specialized.NameValueCollection queryStringData = httpPacket.GetQuerystringData();
                    if (queryStringData != null && queryStringData.Count > 0) {
                        if (httpPacket.RequestedHost?.Length > 0)
                            mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, queryStringData, tcpPacket.ParentFrame.Timestamp, "HTTP QueryString to " + httpPacket.RequestedHost));
                        else
                            mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, queryStringData, tcpPacket.ParentFrame.Timestamp, "HTTP QueryString"));
                        //mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, queryStringData, tcpPacket.ParentFrame.Timestamp, "HTTP QueryString"));
                        NetworkCredential credential = NetworkCredential.GetNetworkCredential(queryStringData, sourceHost, destinationHost, "HTTP GET QueryString", tcpPacket.ParentFrame.Timestamp, httpPacket.RequestedHost);
                        if (credential != null)
                            mainPacketHandler.AddCredential(credential);
                        if (queryStringData.HasKeys()) {
                            this.ExtractHostDetailsFromQueryString(sourceHost, queryStringData, out Dictionary<string, string> queryStringDictionary);


                            if (httpPacket.RequestMethod == Packets.HttpPacket.RequestMethods.POST && queryStringDictionary.ContainsKey("a") && queryStringDictionary["a"].Equals("SendMessage")) {
                                if (!httpPacket.ContentIsComplete())//we must have all the content when parsing AOL data
                                    return false;
                            }
                        }
                    }

                    //file transfer stuff
                    (string filename, string fileLocation) = GetFilenameAndLocation(httpPacket.RequestedFileName);


                    //I will have to switch source and destination host here since this is only the request, not the actual file transfer!
                    try {
                        string fileDetails = httpPacket.RequestedFileName;
                        if (httpPacket.RequestedHost != null && httpPacket.RequestedHost.Length > 0 && httpPacket.RequestedFileName != null && httpPacket.RequestedFileName.StartsWith("/"))
                            fileDetails = httpPacket.RequestedHost + httpPacket.RequestedFileName;
                        FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(mainPacketHandler.FileStreamAssemblerList, fiveTuple, !transferIsClientToServer, FileTransfer.FileStreamTypes.HttpGetNormal, filename, fileLocation, fileDetails, httpPacket.ParentFrame.FrameNumber, httpPacket.ParentFrame.Timestamp, httpPacket.RequestedHost);
                        //mainPacketHandler.FileStreamAssemblerList.Add(assembler);
                        mainPacketHandler.FileStreamAssemblerList.AddOrEnqueue(assembler);

                    }
                    catch (Exception e) {
                        mainPacketHandler.OnAnomalyDetected("Error creating assembler for HTTP file transfer: " + e.Message);

                    }


                    //Large HTTP POSTs should also be dumped to files
                    if (httpPacket.RequestMethod == Packets.HttpPacket.RequestMethods.POST || httpPacket.RequestMethod == Packets.HttpPacket.RequestMethods.PUT) {

                        //All Multipart MIME HTTP POSTs should be dumped to file
                        //the fileAssembler extracts the form parameters after assembly
                        if (httpPacket.ContentType != null && httpPacket.ContentType.StartsWith("multipart/form-data", StringComparison.InvariantCultureIgnoreCase)) {
                            FileTransfer.FileStreamAssembler assembler = null;
                            try {
                                //see if there is an old assembler that needs to be removed
                                if (mainPacketHandler.FileStreamAssemblerList.ContainsAssembler(fiveTuple, transferIsClientToServer)) {
                                    FileTransfer.FileStreamAssembler oldAssembler = mainPacketHandler.FileStreamAssemblerList.GetAssembler(fiveTuple, transferIsClientToServer);
                                    if (oldAssembler.IsActive && oldAssembler.AssembledByteCount > 0) {
                                        //I'll assume that the file transfer was OK
                                        assembler.FinishAssembling();
                                    }
                                    mainPacketHandler.FileStreamAssemblerList.Remove(oldAssembler, true);
                                }

                                string mimeBoundary = "";
                                if (httpPacket.ContentType.ToLower(System.Globalization.CultureInfo.InvariantCulture).StartsWith("multipart/form-data; boundary=") && httpPacket.ContentType.Length > 30) {
                                    mimeBoundary = httpPacket.ContentType.Substring(30);
                                }
                                else {
                                    int multipartIndex = httpPacket.ContentType.IndexOf("multipart/form-data", StringComparison.InvariantCultureIgnoreCase);
                                    if (multipartIndex >= 0) {
                                        int boundaryIndex = httpPacket.ContentType.IndexOf("boundary=", multipartIndex, StringComparison.InvariantCultureIgnoreCase);
                                        if (boundaryIndex > 0)
                                            mimeBoundary = httpPacket.ContentType.Substring(boundaryIndex + 9);
                                    }
                                }

                                assembler = new FileTransfer.FileStreamAssembler(mainPacketHandler.FileStreamAssemblerList, fiveTuple, transferIsClientToServer, FileTransfer.FileStreamTypes.HttpPostMimeMultipartFormData, filename + ".form-data.mime", fileLocation, httpPacket.RequestedFileName, httpPacket.ParentFrame.FrameNumber, httpPacket.ParentFrame.Timestamp) {
                                    MimeBoundary = mimeBoundary,
                                    FileContentLength = httpPacket.ContentLength,
                                    FileSegmentRemainingBytes = httpPacket.ContentLength
                                };
                                mainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                if (assembler.TryActivate()) {
                                    //assembler is now active
                                    if (httpPacket.MessageBody != null && httpPacket.MessageBody.Length > 0)
                                        assembler.AddData(httpPacket.MessageBody, tcpPacket.SequenceNumber);
                                }

                            }
                            catch (Exception e) {
                                if (assembler != null)
                                    assembler.Clear();
                                mainPacketHandler.OnAnomalyDetected("Error creating assembler for HTTP file transfer: " + e.Message);

                            }

                        }
                        else if (httpPacket.ContentType?.StartsWith("application/json", StringComparison.InvariantCultureIgnoreCase) == true && httpPacket.MessageBody?.Length > 0 && httpPacket.MessageBody?.Length == httpPacket.ContentLength) {
                            //extract JSON post parameters
                            System.Collections.Specialized.NameValueCollection jsonPostElements = null;
                            //= new System.Collections.Specialized.NameValueCollection();
                            if (httpPacket.ContentEncoding?.Equals("gzip") == true) {
                                using (System.IO.MemoryStream ms = new System.IO.MemoryStream(httpPacket.MessageBody))
                                using (System.IO.Compression.GZipStream decompressed = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress))
                                using (System.Xml.XmlReader jsonReader = System.Runtime.Serialization.Json.JsonReaderWriterFactory.CreateJsonReader(decompressed, new System.Xml.XmlDictionaryReaderQuotas())) {
                                    jsonPostElements = this.GetJsonParams(jsonReader);
                                }
                            }
                            else {
                                using (System.Xml.XmlReader jsonReader = System.Runtime.Serialization.Json.JsonReaderWriterFactory.CreateJsonReader(httpPacket.MessageBody, new System.Xml.XmlDictionaryReaderQuotas())) {
                                    jsonPostElements = this.GetJsonParams(jsonReader);
                                }
                            }
                            if (jsonPostElements?.Count > 0) {
                                mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, fiveTuple.Transport, tcpPacket.SourcePort, tcpPacket.DestinationPort, jsonPostElements, tcpPacket.ParentFrame.Timestamp, "HTTP POST JSON to " + httpPacket.RequestedHost));

                                NetworkCredential jsonCredential = NetworkCredential.GetNetworkCredential(jsonPostElements, sourceHost, destinationHost, "HTTP POST JSON", httpPacket.ParentFrame.Timestamp);
                                if (jsonCredential != null)
                                    mainPacketHandler.AddCredential(jsonCredential);
                            }
                        }
                        else if (httpPacket.ContentType?.ToLower().Contains("www-form-urlencoded") == true && httpPacket.ContentLength > 0 && httpPacket.MessageBody?.Length >= httpPacket.ContentLength) {//form data (not multipart)
                            System.Collections.Generic.List<Mime.MultipartPart> formMultipartData = httpPacket.GetFormData();
                            if (formMultipartData != null) {
                                foreach (Mime.MultipartPart mimeMultipart in formMultipartData) {
                                    if (mimeMultipart.Attributes["requests"] != null && httpPacket.GetQuerystringData() != null && httpPacket.GetQuerystringData()["a"] == "SendMessage") {
                                        //To handle AOL webmail
                                        string encodedMessage = mimeMultipart.Attributes["requests"];
                                        if (encodedMessage.StartsWith("[{") && encodedMessage.EndsWith("}]")) {
                                            encodedMessage = encodedMessage.Substring(2, encodedMessage.Length - 4);
                                        }
                                        int startIndex = -1;
                                        int endIndex = -1;
                                        while (endIndex < encodedMessage.Length - 2) {
                                            //startIndex = endIndex + 1;
                                            if (endIndex > 0)
                                                startIndex = encodedMessage.IndexOf(',', endIndex) + 1;
                                            else
                                                startIndex = 0;
                                            bool escapedString = encodedMessage[startIndex] == '\"';
                                            if (escapedString) {
                                                startIndex = encodedMessage.IndexOf('\"', startIndex) + 1;
                                                endIndex = encodedMessage.IndexOf('\"', startIndex);
                                                while (encodedMessage[endIndex - 1] == '\\') {
                                                    endIndex = encodedMessage.IndexOf('\"', endIndex + 1);
                                                }
                                            }
                                            else
                                                endIndex = encodedMessage.IndexOf(':', startIndex);

                                            string attributeName = encodedMessage.Substring(startIndex, endIndex - startIndex);

                                            startIndex = encodedMessage.IndexOf(':', endIndex) + 1;
                                            escapedString = encodedMessage[startIndex] == '\"';
                                            if (escapedString) {
                                                startIndex = encodedMessage.IndexOf('\"', startIndex) + 1;
                                                endIndex = encodedMessage.IndexOf('\"', startIndex);
                                                while (encodedMessage[endIndex - 1] == '\\') {
                                                    endIndex = encodedMessage.IndexOf('\"', endIndex + 1);
                                                }
                                            }
                                            else if (encodedMessage.IndexOf(',', startIndex) > 0)
                                                endIndex = encodedMessage.IndexOf(',', startIndex);
                                            else
                                                endIndex = encodedMessage.Length;

                                            string attributeValue = encodedMessage.Substring(startIndex, endIndex - startIndex);
                                            //replace some special characters
                                            encodedMessage = encodedMessage.Replace("\\n", System.Environment.NewLine).Replace("\\r", "\r").Replace("\\t", "\t");
                                            mimeMultipart.Attributes.Add(attributeName, attributeValue);
                                        }
                                        //END OF AOL WEBMAIL CODE

                                    }
                                }
                                this.MainPacketHandler.ExtractMultipartFormData(formMultipartData, fiveTuple, transferIsClientToServer, tcpPacket.ParentFrame.Timestamp, httpPacket.ParentFrame.FrameNumber, ApplicationLayerProtocol.HTTP, cookieParams, httpPacket.RequestedHost);
                            }
                        }
                        else {
                            //extract other posted data to file
                            if (httpPacket.ContentLength > 0) {
                                filename = AppendMimeContentTypeAsExtension(filename, httpPacket.ContentType);
                                FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(mainPacketHandler.FileStreamAssemblerList, fiveTuple, transferIsClientToServer, FileTransfer.FileStreamTypes.HttpPostUpload, filename, fileLocation, "HTTP " + httpPacket.RequestMethod.ToString(), httpPacket.ParentFrame.FrameNumber, httpPacket.ParentFrame.Timestamp);
                                assembler.FileContentLength = httpPacket.ContentLength;
                                assembler.FileSegmentRemainingBytes = httpPacket.ContentLength;
                                mainPacketHandler.FileStreamAssemblerList.Add(assembler);
                                if (assembler.TryActivate()) {
                                    //assembler is now active
                                    if (httpPacket.MessageBody != null && httpPacket.MessageBody.Length > 0)
                                        assembler.AddData(httpPacket.MessageBody, tcpPacket.SequenceNumber);
                                }
                            }

                        }
                    }
                }

                else if (httpPacket.RequestMethod == Packets.HttpPacket.RequestMethods.CONNECT) {
                    this.ExtractHeaders(httpPacket, fiveTuple, transferIsClientToServer, sourceHost, destinationHost);

                    string hostAndPort = httpPacket.RequestedFileName;
                    //string hostAndPort = httpPacket..reqrequestString.Split(" ")?.Skip(1)?.FirstOrDefault();
                    if (!string.IsNullOrEmpty(hostAndPort)) {
                        string targetHost;
                        ushort targetPort = 80;//default value
                        if (hostAndPort.Contains(':')) {
                            string[] hp = hostAndPort.Split(':');
                            targetHost = hp[0];
                            _ = ushort.TryParse(hp[1], out targetPort);
                        }
                        else
                            targetHost = hostAndPort;

                        if (!this.httpConnectIpPorts.ContainsKey(fiveTuple))
                            this.httpConnectIpPorts[fiveTuple] = new KeyValuePair<string, ushort>(targetHost, targetPort);
                    }
                    
                }

            }
            else {//reply
                try {
                    System.Collections.Specialized.NameValueCollection httpResponseNvc = new System.Collections.Specialized.NameValueCollection();
                    httpResponseNvc.Add("HTTP Response Status Code", httpPacket.StatusCode + " " + httpPacket.StatusMessage);
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(httpPacket.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, httpResponseNvc, httpPacket.ParentFrame.Timestamp, "HTTP Response"));

                    this.ExtractHeaders(httpPacket, fiveTuple, transferIsClientToServer, sourceHost, destinationHost);
                    

                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error parsing HTTP reply packet of " + httpPacket.ParentFrame.ToString() + ". " + e.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
                };
                if (httpPacket.ServerBanner != null && httpPacket.ServerBanner.Length > 0)
                    sourceHost.AddHttpServerBanner(httpPacket.ServerBanner, tcpPacket.SourcePort);
                if (httpPacket.WwwAuthenticateRealm != null && httpPacket.WwwAuthenticateRealm.Length > 0) {
                    sourceHost.AddHostName(httpPacket.WwwAuthenticateRealm, httpPacket.PacketTypeDescription);
                    sourceHost.AddNumberedExtraDetail("WWW-Authenticate realm", httpPacket.WwwAuthenticateRealm);
                }
                if (mainPacketHandler.FileStreamAssemblerList.ContainsAssembler(fiveTuple, transferIsClientToServer)) {
                    FileTransfer.FileStreamAssembler assembler = mainPacketHandler.FileStreamAssemblerList.GetAssembler(fiveTuple, transferIsClientToServer);

                    //http://www.mail-archive.com/wireshark-dev@wireshark.org/msg08695.html
                    //There could also be no content-length when http-keepalives are not used.
                    //In that case, the client just collects all data till the TCP-FIN.
                    //-1 is set instead of null if Content-Length is not defined
                    if (httpPacket.StatusCode != null && httpPacket.StatusCode.Trim().StartsWith("1")) {
                        //just ignore this response, probably a "HTTP/1.1 100 Continue"
                    }
                    if (httpPacket.StatusCode != null && httpPacket.StatusCode.Trim().StartsWith("204")) {
                        //HTTP/1.1 204 No Content
                        mainPacketHandler.FileStreamAssemblerList.Remove(assembler, true);
                    }
                    else if (httpPacket.StatusCode != null && !httpPacket.StatusCode.Trim().StartsWith("2") && httpPacket.ContentLength <= 0 && httpPacket.TransferEncoding == null)
                        mainPacketHandler.FileStreamAssemblerList.Remove(assembler, true);
                    else {
                        if (httpPacket.ContentLength >= 0 || httpPacket.ContentLength == -1) {
                            assembler.FileContentLength = httpPacket.ContentLength;
                            assembler.FileSegmentRemainingBytes = httpPacket.ContentLength;//we get the whole file in one segment (one serie of TCP packets)
                        }

                        if (httpPacket.ContentLength == 0) {
                            mainPacketHandler.FileStreamAssemblerList.Remove(assembler, true);
                        }
                        else {
                            if (httpPacket.ContentRange != null) {
                                assembler.ContentRange = httpPacket.ContentRange;

                            }

                            if (httpPacket.ContentDispositionFilename != null) {
                                assembler.Filename = httpPacket.ContentDispositionFilename;

                            }
                            //append content type extention to file name
                            assembler.Filename = AppendMimeContentTypeAsExtension(assembler.Filename, httpPacket.ContentType);


                            if (httpPacket.TransferEncoding == "chunked")
                                assembler.FileStreamType = FileTransfer.FileStreamTypes.HttpGetChunked;
                            if (httpPacket.ContentEncoding != null && httpPacket.ContentEncoding.Length > 0) {
                                if (httpPacket.ContentEncoding.Equals("gzip"))//I'll only care aboute gzip for now
                                    assembler.ContentEncoding = Packets.HttpPacket.ContentEncodings.Gzip;
                                else if (httpPacket.ContentEncoding.Equals("deflate"))//http://tools.ietf.org/html/rfc1950
                                    assembler.ContentEncoding = Packets.HttpPacket.ContentEncodings.Deflate;
                                else if (httpPacket.ContentEncoding.Equals("br"))//https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
                                    assembler.ContentEncoding = Packets.HttpPacket.ContentEncodings.Brotli;
                            }


                            if (assembler.TryActivate()) {
                                //the assembler is now ready to receive data

                                if (httpPacket.MessageBody != null && httpPacket.MessageBody.Length > 0) {
                                    if (assembler.FileStreamType == FileTransfer.FileStreamTypes.HttpGetChunked || httpPacket.MessageBody.Length <= assembler.FileSegmentRemainingBytes || assembler.FileSegmentRemainingBytes == -1)
                                        assembler.AddData(httpPacket.MessageBody, tcpPacket.SequenceNumber);

                                    //check for raw public IP in HTTP Message Body such as from "api.ipify.org", "checkip.amazonaws.com" or "icanhazip.com"
                                    if (httpPacket.MessageBody.Length == httpPacket.ContentLength &&
                                        httpPacket.ContentLength > 6 &&
                                        httpPacket.ContentLength < 18 &&
                                        httpPacket.MessageBody.Count(i => i == (byte)'.') == 3) {

                                        if(System.Net.IPAddress.TryParse(Encoding.ASCII.GetString(httpPacket.MessageBody).TrimEnd(), out System.Net.IPAddress ip)) {
                                            destinationHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, ip.ToString());
                                        }
                                    }
                                    else if (httpPacket.TransferEncoding == "chunked" &&
                                        httpPacket.MessageBody.Length > 14 &&//3 bytes chunk header, 7 bytes IP, 5 bytes chunk trailer
                                        httpPacket.MessageBody.Length < 26 &&//3 bytes chunk header, 15 bytes IP, 2 bytes CR-LF, 5 bytes chunk trailer
                                        HttpPacket.CHUNK_TRAILER.SequenceEqual(httpPacket.MessageBody.Skip(httpPacket.MessageBody.Length - HttpPacket.CHUNK_TRAILER.Length)) &&
                                        httpPacket.MessageBody.Count(i => i == (byte)'.') == 3) {
                                        //Services like ip.anysrc.net send IP address in chunked format
                                        using (MemoryStream ms = new MemoryStream(httpPacket.MessageBody)) {
                                            using (DeChunkedDataStream deChunkedStream = new DeChunkedDataStream(ms)) {
                                                using(StreamReader sr = new StreamReader(deChunkedStream)) {
                                                    string decodedBody = sr.ReadToEnd();
                                                    if (System.Net.IPAddress.TryParse(decodedBody.TrimEnd(), out System.Net.IPAddress ip)) {
                                                        destinationHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, ip.ToString());
                                                    }
                                                }
                                            }
                                        }

                                    }
                                    //try extract IPv4 address from JSON body
                                    if (httpPacket.ContentType?.StartsWith("application/json") == true && httpPacket.ContentLength < 1000) {
                                        //check for hostnames like "ip-api.com" or "ipinfo.io" to reduce false positives from other JSON data
                                        if (sourceHost.HostNames.Any(hostname => hostname.ToUpper().Contains("IP"))) { 
                                            byte[] delimiters = { (byte)'{', (byte)'}', (byte)':', (byte)',', (byte)'"' };
                                            List<byte> stringBytes = new List<byte>();
                                            foreach (byte b in httpPacket.MessageBody) {
                                                if (delimiters.Contains(b)) {
                                                    if (stringBytes.Count >= 7 && stringBytes.Count < 18 && stringBytes.Count(i => i == (byte)'.') == 3)
                                                        if (System.Net.IPAddress.TryParse(Encoding.ASCII.GetString(stringBytes.ToArray()).TrimEnd(), out System.Net.IPAddress ip))
                                                            destinationHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, ip.ToString());
                                                    stringBytes.Clear();
                                                }
                                                else
                                                    stringBytes.Add(b);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else if(this.httpConnectIpPorts.ContainsKey(fiveTuple) && httpPacket.StatusCode.StartsWith("200")) {
                    //TODO: Save state of awaiting CONNECT, after "HTTP/1.1 200 Connection established" switch L7 protocol as in SOCKS and STARTTLS
                    var target = this.httpConnectIpPorts[fiveTuple];
                    ushort serverPort = target.Value;

                    NetworkHost serverHost = sourceHost;
                    if(System.Net.IPAddress.TryParse(target.Key, out var ip)) {
                        if (base.MainPacketHandler.NetworkHostList.ContainsIP(ip))
                            serverHost = base.MainPacketHandler.NetworkHostList.GetNetworkHost(ip);
                        else
                            serverHost = new NetworkHost(ip);
                    }
                    tcpSession.ProtocolFinder = new TcpPortProtocolFinder(tcpSession.Flow, tcpPacket.ParentFrame.FrameNumber, base.MainPacketHandler, serverHost, serverPort);

                }
            }
            return true;
        }

        private void ExtractHeaders(Packets.HttpPacket httpPacket, FiveTuple fiveTuple, bool transferIsClientToServer, NetworkHost sourceHost, NetworkHost destinationHost, SortedList<string, string> ignoredHeaderNames = null) {
            System.Collections.Specialized.NameValueCollection httpHeaders = HttpPacketHandler.ParseHeaders(httpPacket, ignoredHeaderNames);
            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(httpPacket.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, httpHeaders, httpPacket.ParentFrame.Timestamp, "HTTP Header"));
            if (httpPacket.MessageTypeIsRequest) {
                foreach (string headerName in httpHeaders.Keys) {

                    /**
                     * http://mobiforge.com/developing/blog/useful-x-headers
                     * http://nakedsecurity.sophos.com/2012/01/25/smartphone-website-telephone-number/
                     * http://www.nowsms.com/discus/messages/485/14998.html
                     * http://coding-talk.com/f46/check-isdn-10962/
                     **/
                    if (!HttpPacketHandler.BoringXHeaders.Contains(headerName)) {
                        if (headerName.StartsWith("X-", StringComparison.InvariantCultureIgnoreCase)) {
                            sourceHost.AddNumberedExtraDetail("HTTP header: " + headerName, httpHeaders[headerName]);
                        }
                        else if (headerName.StartsWith("HTTP_X", StringComparison.InvariantCultureIgnoreCase)) {
                            sourceHost.AddNumberedExtraDetail("HTTP header: " + headerName, httpHeaders[headerName]);
                        }
                        else if (headerName.StartsWith("X_", StringComparison.InvariantCultureIgnoreCase)) {
                            sourceHost.AddNumberedExtraDetail("HTTP header: " + headerName, httpHeaders[headerName]);
                        }
                        else if (headerName.StartsWith("HTTP_MSISDN", StringComparison.InvariantCultureIgnoreCase)) {
                            sourceHost.AddNumberedExtraDetail("HTTP header: " + headerName, httpHeaders[headerName]);
                        }

                    }
                }
            }
            else {
                if (httpHeaders.AllKeys.Contains("X-Proxy-Origin")) {
                    //193.235.19.252; 193.235.19.252; 538.bm-nginx-loadbalancer.mgmt.fra1; *.adnxs.com; 37.252.172.199:80
                    string ipString = httpHeaders.GetValues("X-Proxy-Origin")?.First().Split(';')?.First();
                    if (!string.IsNullOrEmpty(ipString) && System.Net.IPAddress.TryParse(ipString, out System.Net.IPAddress ip))
                        destinationHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, ip.ToString());
                }
                if (httpHeaders.AllKeys.Contains("X-Akamai-Pragma-Client-IP")) {
                    //X-Akamai-Pragma-Client-IP: 178.162.222.41, 178.162.222.41
                    foreach (string ipString in httpHeaders.GetValues("X-Akamai-Pragma-Client-IP")?.FirstOrDefault()?.Split(',')) {
                        if (!string.IsNullOrEmpty(ipString) && System.Net.IPAddress.TryParse(ipString.Trim(), out System.Net.IPAddress ip))
                            destinationHost.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, ip.ToString());
                    }
                }
                if (httpHeaders.AllKeys.Contains("Onion-Location")) {
                    Uri onionUri = new Uri(httpHeaders["Onion-Location"]);
                    sourceHost.AddHostName(onionUri.Host, httpPacket.PacketTypeDescription);
                }
                if (httpHeaders.AllKeys.Contains("Location")) {
                    if (Uri.TryCreate(httpHeaders["Location"], UriKind.Absolute, out Uri redirectTarget)) {
                        string query = redirectTarget.Query?.TrimStart('?');
                        if (!string.IsNullOrEmpty(query)) {
                            System.Collections.Specialized.NameValueCollection q = System.Web.HttpUtility.ParseQueryString(query);
                            if (q.HasKeys())
                                this.ExtractHostDetailsFromQueryString(destinationHost, q, out _);
                        }
                    }
                }

                string[] extraDetailsHeaders = { "X-Amz-Cf-Pop" };
                foreach (string headerName in httpHeaders.AllKeys.Intersect(extraDetailsHeaders)) {
                    sourceHost.AddNumberedExtraDetail("HTTP header: " + headerName, httpHeaders[headerName]);
                }
            }
        }

        private void ExtractHostDetailsFromQueryString(NetworkHost httpClient, System.Collections.Specialized.NameValueCollection queryString, out Dictionary<string, string> queryStringDictionary) {
            queryStringDictionary = new Dictionary<string, string>();
            foreach (string key in queryString.AllKeys)
                if(!string.IsNullOrEmpty(key) && !queryStringDictionary.ContainsKey(key))
                    queryStringDictionary.Add(key, queryString[key]);

            if (queryStringDictionary.ContainsKey("utmsr"))
                httpClient.AddNumberedExtraDetail("Screen resolution (Google Analytics)", queryStringDictionary["utmsr"]);
            if (queryStringDictionary.ContainsKey("utmsc"))
                httpClient.AddNumberedExtraDetail("Color depth (Google Analytics)", queryStringDictionary["utmsc"]);
            if (queryStringDictionary.ContainsKey("utmul"))
                httpClient.AddNumberedExtraDetail("Browser language (Google Analytics)", queryStringDictionary["utmul"]);
            if (queryStringDictionary.ContainsKey("utmfl"))
                httpClient.AddNumberedExtraDetail("Flash version (Google Analytics)", queryStringDictionary["utmfl"]);
            if (queryStringDictionary.ContainsKey("mip")) {
                if (System.Net.IPAddress.TryParse(queryStringDictionary["mip"], out System.Net.IPAddress ip))
                    httpClient.AddNumberedExtraDetail(NetworkHost.ExtraDetailType.PublicIP, queryStringDictionary["mip"]);
            }
        }

        private System.Collections.Specialized.NameValueCollection GetJsonParams(System.Xml.XmlReader jsonReader) {
            System.Collections.Specialized.NameValueCollection jsonElements = new System.Collections.Specialized.NameValueCollection();
            System.Xml.Linq.XElement x = System.Xml.Linq.XElement.Load(jsonReader);
            if (!x.HasElements && !string.IsNullOrEmpty(x.Name.ToString()) && !string.IsNullOrEmpty(x.Value))
                jsonElements.Add(x.Name.ToString(), x.Value);

            foreach (var elem in x.Descendants()) {
                if (!elem.HasElements && !string.IsNullOrEmpty(elem.Name.ToString()) && !string.IsNullOrEmpty(elem.Value))
                    jsonElements.Add(elem.Name.ToString(), elem.Value);

            }
            return jsonElements;
        }



        #endregion
    }
}
