//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Linq;
using System.Text;

namespace PacketParser.FileTransfer {


    public class FileStreamAssembler : IDisposable {

        public delegate void FileReconsructedEventHandler(string extendedFileId, ReconstructedFile file);

        public event FileReconsructedEventHandler FileReconstructed;


        public const string ASSMEBLED_FILES_DIRECTORY = "AssembledFiles";

        //Applications: “.exe”, “.pif”, “.application”, “.gadget”, “.msi”, “.msp”, “.com”, “.scr”, “.hta”, “.cpl”, “.msc”, “.jar”
        //Scripts: “.bat”, “.cmd”, “.vb”, “.vbs”, “.vbe”, “.js”, “.jse”, “.ws”, “.wsf”, “.wsc”, “.wsh”,
        //         “.ps1”, “.ps1xml”, “.ps2”, “.ps2xml”, “.psc1”, “.psc2”, “.msh”, “.msh1”, “.msh2”, “.mshxml”, “.msh1xml”, “.msh2xml”
        //good source: http://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows/
        //another source: https://circl.lu/pub/tr-41/#proactive-measures-for-the-wannacry-ransomware
        internal static readonly string[] executableExtensions = {
            "exe", "bat", "msi", "vb", "vbe", "vbs", "pif", "com", "scr", "jar", "cmd", "js", "jse",
            "ps1", "psc1", "application", "gadget", "msp", "hta", "cpl", "msc",
            "ws", "wsf", "wsc", "wsh", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "msh", "msh1", "msh2", "mshxml", "msh1xml", "msh2xml"
        };

        public static IReadOnlyCollection<string> ExecutableExtensions = new HashSet<string>(executableExtensions);

        public enum FileAssmeblyRootLocation { cache, source, destination };

        /**
         * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
         * 
         * The following reserved characters:
         *     < (less than)
         *     > (greater than)
         *     : (colon)
         *     " (double quote)
         *     / (forward slash)
         *     \ (backslash)
         *     | (vertical bar or pipe)
         *     ? (question mark)
         *     * (asterisk)
         *     
         *     Do not use the following reserved names for the name of a file:
         *     CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
         *     LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, and LPT9
         **/


        private static readonly char[] SPECIAL_CHARACTERS = { ':', '*', '?', '"', '<', '>', '|' };
        private static readonly char[] DIRECTORY_SEPARATORS = { '\\', '/' };
        private static readonly string[] FORBIDDEN_NAMES = { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };

        public static string GetExtensionFromHeader(byte[] header) {
            if (header.Length >= 8) {
                ulong headerValue = Utils.ByteConverter.ToUInt64(header, 0, false);
                for (int i = 8; i > 3 && headerValue > 0; i--) {
                    if (FileHeaders.ContainsKey(headerValue)) {
                        if (FileHeaders[headerValue].Equals("exe", StringComparison.InvariantCultureIgnoreCase) && IsDLL(header))
                            return "dll";
                        return FileHeaders[headerValue];
                    }
                    headerValue >>= 8;
                }
            }
            return null;
        }

        private static bool IsDLL(byte[] header) {
            //https://what-when-how.com/windows-forensic-analysis/executable-file-analysis-windows-forensic-analysis-part-2/
            //https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#characteristics
            //LONG e_lfanew is at offset 60
            if (header.Length < 64 + 24)
                return false;
            uint e_lfanew = Utils.ByteConverter.ToUInt32(header, 60, 4, true);
            if (header.Length < e_lfanew + 24)
                return false;
            //verify PE header
            byte[] peHeader = { 0x50, 0x45, 0x00, 0x00 };
            if (!header.Skip((int)e_lfanew).Take(4).SequenceEqual(peHeader))
                return false;
            //Characteristics is at offset 22 from PE header, but we only need the last Characteristics byte (most significant)
            byte CharacteristicsHigh = header[e_lfanew + 23];
            const byte IMAGE_FILE_DLL_HIGH = 0x20;
            return (CharacteristicsHigh & IMAGE_FILE_DLL_HIGH) == IMAGE_FILE_DLL_HIGH;
        }


        //https://en.wikipedia.org/wiki/List_of_file_signatures
        private static readonly Dictionary<UInt64, string> FileHeaders = new Dictionary<UInt64, string> {
            { 0x667479703367, "3gp" },
            { 0x377ABCAF271C, "7z" },
            { 0x4D534346, "cab" },
            { 0x49536328, "cab" },
            { 0x5F434153455F, "cas" },
            { 0xCAFEBABE, "class" },//https://stackoverflow.com/questions/2808646/why-are-the-first-four-bytes-of-the-java-class-file-format-cafebabe
            { 0x43723234, "crx" },//https://www.dre.vanderbilt.edu/~schmidt/android/android-4.0/external/chromium/chrome/common/extensions/docs/crx.html
            { 0x4349534F, "cso" },
            { 0x504D4F43434D4F43, "dat" },
            { 0x213C617263683E0A, "deb" },
            { 0x6465780A30333500, "dex" },
            { 0x6465780a, "dex" },
            { 0x6465790a, "dex" },
            { 0xD0CF11E0A1B1, "doc" },
            { 0xD0CF11E0A1B11AE1, "doc" }, //could also be xls, ppt, msi or msg
            //{ 0xD0CF11E0A1B11AE1, "xls" },
            //{ 0xD0CF11E0A1B11AE1, "ppt" },
            //{ 0xD0CF11E0A1B11AE1, "msi" },
            { 0x504B030414000600, "docx" },
            { 0x4d5a9000, "exe" }, //could also be .dll
            { 0x4d5a8000, "exe" }, //could also be .dll
            { 0x4d5a5000, "exe" }, //could also be .dll
            { 0x4d5a0000, "exe" },
            { 0x7F454C46, "elf" },
            { 0x464C5601, "flv" }, //https://raw.githubusercontent.com/corkami/pocs/master/mocks/flv.bin
            { 0x474946383761, "gif" },
            { 0x474946383961, "gif" },
            { 0x1F8B0800, "gz" },//prevents Content-Encoding gzip from getting proper extension after decompression
            { 0x1F8B0808, "gz" },
            //{ 0x3c3f786d6c20, "html"},//"<?xml " this could also be SVG!
            { 0x3c21444f43545950, "html" }, //"<!DOCTYP" which should be followed by "E html>"
            { 0x3c68746d6c, "html" }, //"<html
            { 0x3c48544d4c, "html" }, //"<HTML"
            { 0x504943540008, "img" },
            { 0x514649FB, "img" },
            { 0x53434D49, "img" },
            { 0x4344303031, "iso" },
            { 0x00000100, "ico" },
            { 0x4A4152435300, "jar" },
            { 0x5F27A889, "jar" },
            { 0xFFD8FFDB, "jpg" },
            { 0xFFD8FFE000104A46, "jpg" },
            { 0xFFD8FFE00010, "jpg" },
            { 0xFFD8FFE135FE, "jpg" },
            { 0xFFD8FFE1, "jpg"},
            { 0x49460001FFD8FFEE, "jpg" },
            //{ 0xD8FFE000104A4649, "jpg" },//broken jpg?
            { 0x4C5A4950, "lz" },
            { 0x04224D18, "lz4" },
            { 0x1A45DFA393428288, "mkv" },
            { 0xFFFE23006C006900, "mof" },
            { 0x4944330300000000, "mp3" },
            { 0xfffb906400000000, "mp3" },
            { 0xfffb90440000, "mp3" },
            { 0x0000001466747970, "mp4" },//ISO(?)
            { 0x0000001866747970, "mp4" },
            { 0x0000001C66747970, "mp4" },
            { 0x000001BA, "mpg" },
            { 0x000001B3, "mpg" },
            { 0x4E504400, "npd" },//https://github.com/windsurfer1122/PSN_get_pkg_info/blob/master/PSN_get_pkg_info.py
            { 0x4F676753, "ogg" },
            { 0x00504250, "pbp" },//https://github.com/windsurfer1122/PSN_get_pkg_info/blob/master/PSN_get_pkg_info.py
            { 0xD4C3B2A1, "pcap" },
            { 0xA1B2C3D4, "pcap" },
            { 0x4D3CB2A1, "pcap" },
            { 0xA1B23C4D, "pcap" },
            { 0x34CDB2A1, "pcap" },//FRITZ!Box little endian
            { 0xA1B2CD34, "pcap" },//FRITZ!Box big endian
            { 0x0A0D0D0A, "pcapng" },
            { 0x25504446, "pdf" },
            { 0x255044462D, "pdf" },
            { 0x3C3F706870, "php" },//<?php
            { 0x7f504b47, "pkg3" },//https://github.com/windsurfer1122/PSN_get_pkg_info/blob/master/PSN_get_pkg_info.py
            { 0x7f657874, "pkg3" },//https://github.com/windsurfer1122/PSN_get_pkg_info/blob/master/PSN_get_pkg_info.py
            { 0x7f434e54, "pkg4" },//https://github.com/windsurfer1122/PSN_get_pkg_info/blob/master/PSN_get_pkg_info.py
            { 0x89504E470D0A1A0A, "png" },
            { 0x52457e5e, "rar" },//RAR v1.4
            { 0x526172211A0700, "rar" },//RAR v4
            { 0x526172211A070100, "rar" },//RAR v5
            //{ 0x52457e5e, "rar" },
            { 0xEDABEEDB, "rpm" },
            { 0x7B5C7274, "rtf" },
            { 0x00505346, "sfo" },//https://github.com/windsurfer1122/PSN_get_pkg_info/blob/master/PSN_get_pkg_info.py
            { 0x46575304, "swf" },
            { 0x46575305, "swf" },
            { 0x46575306, "swf" },
            { 0x46575307, "swf" },
            { 0x46575308, "swf" },
            { 0x46575309, "swf" },
            { 0x25215053, "ps" },
            { 0x7573746172003030, "tar" },
            { 0x7573746172202000, "tar" },
            { 0x49492A00, "tiff" },
            { 0x4D4D002A, "tiff" },
            { 0x0061736d, "wasm" }, //https://github.com/corkami/pocs/blob/master/mocks/wasm.bin
            { 0x1a45dfa301428200, "webm" },
            { 0x1A45DFA3, "webm" },
            { 0x4D5357494D, "wim" },
            //{ 0x52494646, "wav" },//could also be avi
            { 0x3026B275, "wma" },
            { 0x3026B2758E66CF11, "wmv" },
            { 0x0000002066747970, "m4a" },
            { 0x78617221, "xar" },
            { 0xFD377A585A00, "xz" },
            { 0x504B0304, "zip" },
            { 0x504B0506, "zip" },
            { 0x504B0708, "zip" },
            { 0x504B030414000100, "zip" },
            {0, null }
        };
        private Packets.HttpPacket.ContentEncodings contentEncoding;
        private string filename, fileLocation;
        private string extendedFileId;
        //private bool reassembleFileAtSourceHost;
        private FileAssmeblyRootLocation fileAssmeblyRootLocation;
        private readonly string serverHostname;//host header in HTTP
        private System.IO.FileStream fileStream;
        private readonly SortedList<uint, byte[]> tcpPacketBufferWindow;

        internal NetworkHost SourceHost {
            get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ClientHost;
                else
                    return this.FiveTuple.ServerHost;
            }
        }
        internal NetworkHost DestinationHost {
            get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ServerHost;
                else
                    return this.FiveTuple.ClientHost;
            }
        }
        internal ushort SourcePort {
            get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ClientPort;
                else

                    return this.FiveTuple.ServerPort;
            }
        }
        internal ushort DestinationPort {
            get {
                if (this.TransferIsClientToServer)
                    return this.FiveTuple.ServerPort;
                else
                    return this.FiveTuple.ClientPort;
            }
        }
        internal string ExtensionFromHeader { get; private set; } = null;
        internal string Filename {
            get { return this.filename; }
            set {
                this.filename = value;
                if (this.fileLocation != null && this.fileLocation.Length > 0 && this.filename != null)
                    FixFilenameAndLocation(ref this.filename, ref this.fileLocation, this.ExtensionFromHeader);
            }
        }
        internal string FileLocation { get { return this.fileLocation; } }
        internal string Details { get; }
        internal string MimeBoundary { get; set; }
        internal FiveTuple FiveTuple { get; }
        internal bool TransferIsClientToServer { get; }
        internal long FileContentLength { get; set; }
        internal long FileSegmentRemainingBytes { get; set; }
        internal int AssembledByteCount { get; private set; }
        internal FileStreamTypes FileStreamType { get; set; }

        /// <summary>
        /// Indicates if length fields are sent along with data to AddData()
        /// </summary>
        internal bool IsSegmentLengthDataTransferType {
            get {
                return this.FileStreamType == FileStreamTypes.HttpGetChunked ||
                    this.FileStreamType == FileStreamTypes.TFTP ||
                    this.FileStreamType == FileStreamTypes.IEC104;
            }
        }

        internal Packets.HttpPacket.ContentEncodings ContentEncoding {
            get { return this.contentEncoding; }
            set {
                this.contentEncoding = value;
                if (value == Packets.HttpPacket.ContentEncodings.Gzip && !this.ParentAssemblerList.DecompressGzipStreams && !this.filename.EndsWith(".gz"))
                    this.filename += ".gz";
                else if (value == Packets.HttpPacket.ContentEncodings.Brotli && !this.filename.EndsWith(".br"))
                    this.filename += ".br";
            }
        }
        internal bool IsActive { get; private set; }
        internal string ExtendedFileId {
            get {
                if (this.extendedFileId == null)
                    return string.Empty;
                else
                    return this.extendedFileId;
            }
            set { this.extendedFileId = value; }
        }
        internal FileStreamAssemblerList ParentAssemblerList { get; }
        internal long InitialFrameNumber { get; }
        internal DateTime Timestamp { get; }

        internal ContentRange ContentRange { set; get; }

        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, string details, long initialFrameNumber, DateTime timestamp, string serverHostname = null)
            :
            this(parentAssemblerList, fiveTuple, transferIsClientToServer, fileStreamType, filename, fileLocation, 0, 0, details, null, initialFrameNumber, timestamp, FileAssmeblyRootLocation.source, serverHostname) {
        }
        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, string details, long initialFrameNumber, DateTime timestamp, FileAssmeblyRootLocation fileAssmeblyRootLocation)
            :
            this(parentAssemblerList, fiveTuple, transferIsClientToServer, fileStreamType, filename, fileLocation, 0, 0, details, null, initialFrameNumber, timestamp, fileAssmeblyRootLocation) {
        }

        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, string details, string extendedFileId, long initialFrameNumber, DateTime timestamp)
            :
            this(parentAssemblerList, fiveTuple, transferIsClientToServer, fileStreamType, filename, fileLocation, 0, 0, details, extendedFileId, initialFrameNumber, timestamp, FileAssmeblyRootLocation.source) {
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="sourceHost"></param>
        /// <param name="sourcePort"></param>
        /// <param name="destinationHost"></param>
        /// <param name="destinationPort"></param>
        /// <param name="tcpTransfer">True=TCP, False=UDP</param>
        /// <param name="fileStreamType"></param>
        /// <param name="filename">for example "image.gif"</param>
        /// <param name="fileLocation">for example "/images", empty string for root folder</param>
        //internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer, FileStreamTypes fileStreamType, string filename, string fileLocation, long fileContentLength, long fileSegmentRemainingBytes, string details, string extendedFileId, long initialFrameNumber, DateTime timestamp, bool reassembleFileAtSourceHost, string serverHostname = null){
        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, long fileContentLength, long fileSegmentRemainingBytes, string details, string extendedFileId, long initialFrameNumber, DateTime timestamp, FileAssmeblyRootLocation fileAssmeblyRootLocation, string serverHostname = null) {
            this.ParentAssemblerList = parentAssemblerList;
            this.FiveTuple = fiveTuple;
            this.TransferIsClientToServer = transferIsClientToServer;

            this.FileStreamType = fileStreamType;
            this.FileContentLength = fileContentLength;//this one can not be set already when the client requests the file...so it has to be changed later
            this.FileSegmentRemainingBytes = fileSegmentRemainingBytes;
            this.Details = details;
            this.contentEncoding = Packets.HttpPacket.ContentEncodings.Identity;//default
            this.IsActive = false;
            this.extendedFileId = extendedFileId;
            this.InitialFrameNumber = initialFrameNumber;
            this.Timestamp = timestamp;

            this.filename = filename;
            this.fileLocation = fileLocation;
            this.fileAssmeblyRootLocation = fileAssmeblyRootLocation;


            this.serverHostname = serverHostname;



            //I just hate the limitation on file and folder length.
            //See: http://msdn2.microsoft.com/en-us/library/aa365247.aspx
            //Or: http://blogs.msdn.com/bclteam/archive/2007/02/13/long-paths-in-net-part-1-of-3-kim-hamilton.aspx

            //see if there is any fileLocation info in the filename and move it to the fileLocation
            FixFilenameAndLocation(ref this.filename, ref this.fileLocation, this.ExtensionFromHeader);
            SharedUtils.Logger.Log("Creating FileStreamAssembler for file " + this.filename, SharedUtils.Logger.EventLogEntryType.Information);



            this.AssembledByteCount = 0;
            this.tcpPacketBufferWindow = new SortedList<uint, byte[]>();

            if (this.IsActive) {
                try {
                    this.fileStream = new System.IO.FileStream(GetFilePath(FileAssmeblyRootLocation.cache).absolutPath, System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite);
                }
                catch (System.UnauthorizedAccessException) {//System.IO.__Error.WinIOError
                    this.ParentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(GetFilePath(FileAssmeblyRootLocation.cache).absolutPath);
                }
            }
            else
                this.fileStream = null;
        }

        public static string UrlEncode(string s) {
            return System.Web.HttpUtility.UrlEncode(s);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="fileHeaderData">At least 8 bytes needed to set extension, but recommended length is 1024 in order to differentiate between DLL and EXE</param>
        /// <param name="filename"></param>
        /// <param name="fileLocation"></param>
        internal static string SetExtensionFromFileHeader(byte[] fileHeaderData, ref string filename, ref string fileLocation) {
            string extensionFromHeader = GetExtensionFromHeader(fileHeaderData);

            if (!string.IsNullOrEmpty(extensionFromHeader) && !filename.EndsWith(extensionFromHeader, StringComparison.InvariantCultureIgnoreCase))
                FixFilenameAndLocation(ref filename, ref fileLocation, extensionFromHeader);
            return extensionFromHeader;
        }

        internal static void FixFilenameAndLocation(ref string filename, ref string fileLocation, string extensionFromHeader = null) {
            if (filename.Contains("/")) {
                fileLocation = filename.Substring(0, filename.LastIndexOf('/') + 1);
                filename = filename.Substring(filename.LastIndexOf('/') + 1);
            }
            if (filename.Contains("\\")) {
                fileLocation = filename.Substring(0, filename.LastIndexOf('\\') + 1);
                filename = filename.Substring(filename.LastIndexOf('\\') + 1);
            }

            filename = System.Web.HttpUtility.UrlDecode(filename);
            while (filename.IndexOfAny(SPECIAL_CHARACTERS) > -1)
                filename = filename.Remove(filename.IndexOfAny(SPECIAL_CHARACTERS), 1);
            while (filename.IndexOfAny(DIRECTORY_SEPARATORS) > -1)
                filename = filename.Remove(filename.IndexOfAny(DIRECTORY_SEPARATORS), 1);
            while (filename.StartsWith("."))
                filename = filename.Substring(1);
            if (!string.IsNullOrEmpty(extensionFromHeader)) {
                if (filename.IndexOf('.') < 0)
                    filename = filename + "." + extensionFromHeader;
                else if (filename.EndsWith(".octet-stream", StringComparison.InvariantCultureIgnoreCase))
                    filename = filename.Substring(0, filename.Length - 12) + extensionFromHeader;
            }

            if (filename.Length > 32) {//not allowed by Windows to be more than 260 characters
                //I want to make sure I keep the extension when the filename is cut...
                int extensionPosition = filename.LastIndexOf('.');
                if (extensionPosition < 0 || extensionPosition <= filename.Length - 20)
                    filename = filename.Substring(0, 20);
                else
                    filename = filename.Substring(0, 20 - filename.Length + extensionPosition) + filename.Substring(extensionPosition);
            }

            //FILE LOCATION
            if (fileLocation == null)
                fileLocation = string.Empty;
            fileLocation = System.Web.HttpUtility.UrlDecode(fileLocation);
            fileLocation = fileLocation.Replace("..", "_");

            fileLocation = fileLocation.Replace('\\', '/');//I prefer using frontslash


            while (fileLocation.IndexOfAny(SPECIAL_CHARACTERS) > -1)
                fileLocation = fileLocation.Remove(fileLocation.IndexOfAny(SPECIAL_CHARACTERS), 1);
            if (fileLocation.Length > 0 && !fileLocation.StartsWith("/"))
                fileLocation = "/" + fileLocation;
            foreach (string forbiddenName in FORBIDDEN_NAMES) {
                int index = fileLocation.IndexOf("/" + forbiddenName + "/", StringComparison.InvariantCultureIgnoreCase);
                if (index >= 0)
                    fileLocation = fileLocation.Substring(0, index + 1) + "_" + fileLocation.Substring(index + 1);
            }
            fileLocation = fileLocation.Replace("/./", "/");//replace "/dir/./sub/" with "/dir/sub"
            while (fileLocation.EndsWith("."))
                fileLocation = fileLocation.Substring(0, fileLocation.Length - 1);
            fileLocation = fileLocation.TrimEnd(DIRECTORY_SEPARATORS);


            if (fileLocation.Length > 40)//248 characters totally (directory + file name) is the maximum allowed
                fileLocation = fileLocation.Substring(0, 40).TrimEnd(DIRECTORY_SEPARATORS);
        }

        internal virtual bool TryActivate() {
            try {
                if (this.fileStream == null) {
                    this.fileStream = new System.IO.FileStream(GetFilePath(FileAssmeblyRootLocation.cache).absolutPath, System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite);
                }
                this.IsActive = true;
                return true;
            }
            catch (System.UnauthorizedAccessException ex) {//System.IO.__Error.WinIOError
                this.ParentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(GetFilePath(FileAssmeblyRootLocation.cache).absolutPath);
                SharedUtils.Logger.Log("UnauthorizedAccessException when activating File Stream Assembler: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                return false;
            }
            catch (Exception ex) {
                this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Unable to create output stream for " + this.fileLocation);
                SharedUtils.Logger.Log("Exception when activating File Stream Assembler: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                return false;
            }
        }

        private void PacketHandler_InsufficientWritePermissionsDetected(string obj) {
            throw new NotImplementedException();
        }

        private (string absolutPath, Uri relativeUri) GetFilePath(FileAssmeblyRootLocation fileAssemblyRootLocation) {
            return GetFilePath(fileAssemblyRootLocation, this.FiveTuple, this.TransferIsClientToServer, this.FileStreamType, this.fileLocation, this.filename, this.ParentAssemblerList, this.ExtendedFileId);
        }

        //internal static string GetFilePath(bool tempCachePath, bool tcpTransfer, System.Net.IPAddress sourceIp, System.Net.IPAddress destinationIp, ushort sourcePort, ushort destinationPort, FileStreamTypes fileStreamType, string fileLocation, string filename, FileStreamAssemblerList parentAssemblerList, string extendedFileId) {
        internal static (string absolutPath, Uri relativeUri) GetFilePath(FileAssmeblyRootLocation fileAssemblyRootLocation, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string fileLocation, string filename, FileStreamAssemblerList parentAssemblerList, string extendedFileId) {
            //sanitize filename
            if (filename.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0) {
                foreach (char c in System.IO.Path.GetInvalidFileNameChars())
                    filename.Replace(c, '_');
            }
            if (parentAssemblerList.PacketHandler.DefangExecutableFiles) {

                foreach (string ext in executableExtensions)
                    if (filename.EndsWith("." + ext, StringComparison.InvariantCultureIgnoreCase))
                        filename += "_";//defanged by adding "_" after the extension
            }

            //sanitize file location
            fileLocation = fileLocation.Replace("..", "_");//just to ensure that no file is written to a parent directory
            fileLocation = fileLocation.Replace("/./", "/").Replace("\\.\\", "\\");//replace "/dir/./sub/" with "/dir/sub"
            while (fileLocation.EndsWith("."))
                fileLocation = fileLocation.Substring(0, fileLocation.Length - 1);
            //remove leading and trainling spaces in directories
            fileLocation = fileLocation.Trim();
            while (fileLocation.Contains("/ "))
                fileLocation = fileLocation.Replace("/ ", "/");
            while (fileLocation.Contains(" /"))
                fileLocation = fileLocation.Replace(" /", "/");
            while (fileLocation.Contains("\\ "))
                fileLocation = fileLocation.Replace("\\ ", "\\");
            while (fileLocation.Contains(" \\"))
                fileLocation = fileLocation.Replace(" \\", "\\");

            if (fileLocation.IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0) {
                foreach (char c in System.IO.Path.GetInvalidPathChars())
                    fileLocation.Replace(c, '_');
            }

            string filePath;
            string protocolString;
            if (fileStreamType == FileStreamTypes.HttpGetNormal || fileStreamType == FileStreamTypes.HttpGetChunked)
                protocolString = "HTTP";
            else if (fileStreamType == FileStreamTypes.HTTP2)
                protocolString = "HTTP/2";
            else if (fileStreamType == FileStreamTypes.SMB)
                protocolString = "SMB";
            else if (fileStreamType == FileStreamTypes.SMB2)
                protocolString = "SMB2";
            else if (fileStreamType == FileStreamTypes.TFTP)
                protocolString = "TFTP";
            else if (fileStreamType == FileStreamTypes.TlsCertificate)
                protocolString = "TLS_Cert";
            else if (fileStreamType == FileStreamTypes.FTP)
                protocolString = "FTP";
            else if (fileStreamType == FileStreamTypes.HttpPostMimeMultipartFormData)
                protocolString = "MIME_form-data";
            else if (fileStreamType == FileStreamTypes.HttpPostMimeFileData)
                protocolString = "MIME_file-data";
            else if (fileStreamType == FileStreamTypes.HttpPostUpload)
                protocolString = "HTTP_POST";
            else if (fileStreamType == FileStreamTypes.Meterpreter)
                protocolString = "Meterpreter";
            else if (fileStreamType == FileStreamTypes.OscarFileTransfer)
                protocolString = "OSCAR";
            else if (fileStreamType == FileStreamTypes.POP3)
                protocolString = "POP3";
            else if (fileStreamType == FileStreamTypes.SMTP)
                protocolString = "SMTP";
            else if (fileStreamType == FileStreamTypes.IMAP)
                protocolString = "IMAP";
            else if (fileStreamType == FileStreamTypes.RTP)
                protocolString = "RTP_VoIP";
            else if (fileStreamType == FileStreamTypes.LPD)
                protocolString = "LPD";
            else if (fileStreamType == FileStreamTypes.IEC104)
                protocolString = "IEC-104";
            else if (fileStreamType == FileStreamTypes.BackConnect)
                protocolString = "BackConnect";
            else if (fileStreamType == FileStreamTypes.njRAT)
                protocolString = "njRAT";
            else if (fileStreamType == FileStreamTypes.VNC)
                protocolString = "VNC";
            else
                throw new Exception("File transfer protocol not implemented yet");

            string transportString = fiveTuple.Transport.ToString();

            System.Net.IPAddress sourceIp, destinationIp;
            ushort sourcePort, destinationPort;
            if (transferIsClientToServer) {
                sourceIp = fiveTuple.ClientHost.IPAddress;
                sourcePort = fiveTuple.ClientPort;
                destinationIp = fiveTuple.ServerHost.IPAddress;
                destinationPort = fiveTuple.ServerPort;
            }
            else {
                destinationIp = fiveTuple.ClientHost.IPAddress;
                destinationPort = fiveTuple.ClientPort;
                sourceIp = fiveTuple.ServerHost.IPAddress;
                sourcePort = fiveTuple.ServerPort;
            }

            if (fileAssemblyRootLocation == FileAssmeblyRootLocation.cache) {
                extendedFileId = Utils.StringManglerUtil.ConvertToFilename(extendedFileId, 10);//truncate to 10 valid filename chars
                filePath = "cache/" + sourceIp.ToString().Replace(':', '-') + "_" + transportString + sourcePort.ToString() + "-" + destinationIp.ToString().Replace(':', '-') + "_" + transportString + destinationPort.ToString() + "_" + protocolString + extendedFileId + ".txt";//with extendedFileId 2011-04-18
            }
            else {
                //this one generates directories like: "/TCP-80/<directory>/<filename>"
                if (fileAssemblyRootLocation == FileAssmeblyRootLocation.source)
                    filePath = sourceIp.ToString().Replace(':', '-') + "/" + transportString + "-" + sourcePort.ToString() + fileLocation + "/" + filename;
                else
                    filePath = destinationIp.ToString().Replace(':', '-') + "/" + transportString + "-" + destinationPort.ToString() + fileLocation + "/" + filename;
                try {
                    System.IO.Path.GetDirectoryName(filePath);
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Error getting directory name of path \"" + filePath + "\".", SharedUtils.Logger.EventLogEntryType.Error);
                    //something could be wrong with the path.. so let's replace it with something that should work better
                    //Examples of things that can go wrong is that the file or directory has a reserved name (like COM2, CON or LPT1) as shown here:
                    //http://www.ureader.com/msg/144639432.aspx
                    //http://msdn.microsoft.com/en-us/library/aa365247(VS.85).aspx
                    //this one generates directories like: "/TCP-80/<directory>/<filename>"
                    filePath = sourceIp.ToString().Replace(':', '-') + "/" + transportString + "-" + sourcePort.ToString() + "/" + System.IO.Path.GetRandomFileName();
                    SharedUtils.Logger.Log("Changing file path to  \"" + filePath + "\".", SharedUtils.Logger.EventLogEntryType.Information);
                }
            }


            filePath = parentAssemblerList.FileOutputDirectory + System.IO.Path.DirectorySeparatorChar + filePath;

            if (System.IO.Path.DirectorySeparatorChar != '/' && filePath.Contains("/"))
                filePath = filePath.Replace('/', System.IO.Path.DirectorySeparatorChar);

            if (fileAssemblyRootLocation != FileAssmeblyRootLocation.cache && System.IO.File.Exists(filePath)) {

                //change filename to avoid overwriting previous files
                int iterator = 1;
                string filePathPrefix;
                string filePathSuffix;//including the "." as in ".txt"
                //now, find the breakpoint in filePath where "[1]" should be inserted
                int extentionPosition = filePath.LastIndexOf('.');//The index position of value if that character is found, or -1 if it is not
                int filenamePosition = filePath.LastIndexOf(System.IO.Path.DirectorySeparatorChar);

                if (extentionPosition < 0) {
                    filePathPrefix = filePath;
                    filePathSuffix = "";
                }
                else if (extentionPosition > filenamePosition) {
                    filePathPrefix = filePath.Substring(0, extentionPosition);
                    filePathSuffix = filePath.Substring(extentionPosition);
                }
                else {
                    filePathPrefix = filePath;
                    filePathSuffix = "";
                }

                string uniqueFilePath = filePathPrefix + "[" + iterator + "]" + filePathSuffix;
                while (System.IO.File.Exists(uniqueFilePath)) {
                    iterator++;
                    uniqueFilePath = filePathPrefix + "[" + iterator + "]" + filePathSuffix;
                }
                filePath = uniqueFilePath;
            }

            Uri relativeFileUri = null;
            if (System.IO.Path.IsPathRooted(filePath)) {
                Uri fileUri = new Uri(filePath);
                Uri outputDirUri = new Uri(parentAssemblerList.FileOutputDirectory);
                if (outputDirUri.IsBaseOf(fileUri)) {
                    relativeFileUri = outputDirUri.MakeRelativeUri(fileUri);
                    //var y = relativeUri.LocalPath;//does not work for relative URI's
                    //var z = relativeUri.AbsolutePath;//does not work for relative URI's
                }
            }

            return (filePath, relativeFileUri);
        }

        internal void SetRemainingBytesInFile(int remainingByteCount) {
            this.FileContentLength = AssembledByteCount + remainingByteCount;
        }

        internal void AddData(Packets.TcpPacket tcpPacket) {
            if (this.FiveTuple.Transport != FiveTuple.TransportProtocol.TCP)
                throw new Exception("No TCP packets accepted, only " + this.FiveTuple.Transport.ToString());
            if (tcpPacket.PayloadDataLength > 0)
                this.AddData(tcpPacket.GetTcpPacketPayloadData(), tcpPacket.SequenceNumber);
        }

        internal void AddData(byte[] packetData, ushort packetNumber) {
            this.AddData(packetData, (uint)packetNumber);
        }
        internal virtual void AddData(byte[] packetData, uint tcpPacketSequenceNumber) {

            if (!this.IsActive) {
                throw new Exception("FileStreamAssembler has not been activated prior to adding data!");
            }
            else {

                if (packetData.Length <= 0)
                    return;//don't do anything with empty packets...
                if (this.tcpPacketBufferWindow.ContainsKey(tcpPacketSequenceNumber))
                    return;//we already have the packet (I'm not putting any effort into seeing if they are different and which one is correct)
                if (!this.IsSegmentLengthDataTransferType && this.FileContentLength != -1) {
                    if (this.FileSegmentRemainingBytes < packetData.Length) {
                        this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Assembler is only expecting data segment length up to " + FileSegmentRemainingBytes + " bytes");
                        return;
                    }
                    this.FileSegmentRemainingBytes -= packetData.Length;
                }

                this.tcpPacketBufferWindow.Add(tcpPacketSequenceNumber, packetData);
                if (this.ExtensionFromHeader == null && this.tcpPacketBufferWindow.Count < 5 && this.tcpPacketBufferWindow.Values.First() == packetData) {
                    this.ExtensionFromHeader = SetExtensionFromFileHeader(packetData, ref this.filename, ref this.fileLocation);
                }
                this.AssembledByteCount += packetData.Length;

                //in order to improve performance I could ofcourse have a separate thread doing all the file operations
                //I'll just simply set the maximum TCP packets stored to 64, this can be adjusted to improve performance.
                //A smaller number gives better performance (both memory and CPU wise) while a larger number gives better tolerance to out-of-order (i.e. non-sequential) TCP packets

                //If this valus is changed, then also make sure to revise "dataListMaxSize" in NetworkTcpSession.TcpDataStream and possibly also "maxPacketFragments" in NetworkTcpSession.VirtualTcpData.TryAppendNextPacket()
                while (this.tcpPacketBufferWindow.Count > 64) {
                    uint key = this.tcpPacketBufferWindow.Keys[0];
                    this.fileStream.Write(this.tcpPacketBufferWindow[key], 0, this.tcpPacketBufferWindow[key].Length);
                    this.tcpPacketBufferWindow.Remove(key);
                }

                FileStreamTypes[] avoidFinishAssemblingTypes = {
                    FileStreamTypes.HttpGetChunked,//calls FinishAssembling explicitly in this function
                    FileStreamTypes.TFTP,//has its own FinishAssembling call
                    FileStreamTypes.RTP,//has its own FinishAssembling call
                    FileStreamTypes.SMB,//closes the assembler when it receives a Packets.SmbPacket.CloseRequest
                    //these types don't even use a FileStreamAssembler
                    FileStreamTypes.HTTP2,//has its own FileSegmentAssembler
                    FileStreamTypes.SMB2,//has its own FileSegmentAssembler
                    FileStreamTypes.IEC104,//has its own FileSegmentAssembler
                    //(HTTP POST has a special case where FinishAssembling if a new POST is made!?!)
                };

                if (this.FileStreamType == FileStreamTypes.HttpGetChunked) {
                    //byte[] chunkTrailer={ 0x30, 0x0d, 0x0a, 0x0d, 0x0a };//see: RFC 2616 3.6.1 Chunked Transfer Coding
                    if (packetData.Length >= Packets.HttpPacket.CHUNK_TRAILER.Length) {
                        bool packetDataHasChunkTrailer = true;
                        for (int i = 0; i < Packets.HttpPacket.CHUNK_TRAILER.Length && packetDataHasChunkTrailer; i++)
                            if (packetData[packetData.Length - Packets.HttpPacket.CHUNK_TRAILER.Length + i] != Packets.HttpPacket.CHUNK_TRAILER[i])
                                packetDataHasChunkTrailer = false;
                        if (packetDataHasChunkTrailer)
                            this.FinishAssembling();

                    }

                }
                else if(this.AssembledByteCount >= this.FileContentLength && this.FileContentLength != -1 && !avoidFinishAssemblingTypes.Contains(this.FileStreamType)) {//we have received the whole file
                    /* This code previously checked if this.FileStreamType was equal to any of these values:
                     * FileStreamTypes.HttpGetNormal
                     * FileStreamTypes.IMAP
                     * FileStreamTypes.LPD
                     * FileStreamTypes.POP3
                     * FileStreamTypes.SMTP
                     * FileStreamTypes.TlsCertificate
                     * FileStreamTypes.FTP
                     * FileStreamTypes.HttpPostMimeMultipartFormData
                     * FileStreamTypes.HttpPostMimeFileData
                     * FileStreamTypes.HttpPostUpload
                     * FileStreamTypes.Meterpreter
                     * FileStreamTypes.BackConnect
                     * FileStreamTypes.njRAT
                     * FileStreamTypes.VNC
                     * FileStreamTypes.OscarFileTransfer
                     */
                    this.FinishAssembling();
                }
                else if (!this.IsSegmentLengthDataTransferType && this.FileSegmentRemainingBytes == 0) {
                    //Ensures we don't have HttpGetChunked, TFTP, IEC104
                    this.IsActive = false;
                }
            }
        }




        /// <summary>
        /// Closes the fileStream and removes the FileStreamAssembler from the parentAssemblerList
        /// </summary>
        public void FinishAssembling() {


            this.IsActive = false;
            if (this.fileStream != null) {
                try {
                    foreach (byte[] data in this.tcpPacketBufferWindow.Values)
                        this.fileStream.Write(data, 0, data.Length);
                    this.fileStream.Flush();
                }
                catch (Exception ex) {
                    if (this.fileStream != null)
                        this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error writing final data to file \"" + fileStream.Name + "\".\n" + ex.Message);
                    else
                        this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error writing final data to file \"" + this.filename + "\".\n" + ex.Message);
                }
            }
            this.tcpPacketBufferWindow.Clear();
            this.ParentAssemblerList.Remove(this, false);

            (string destinationPath, Uri destinationRelativeUri) = this.GetFilePath(this.fileAssmeblyRootLocation);

            /*
#if DEBUG
            //overflow the 260 char path limit
            destinationPath = destinationPath + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.raw";
#endif
            */


            //this.filename might now be "index.html" but destinationPath might end with "index.html[1]"
            //I need to create the directory here since the file might either be moved to this located or a new file will be created there from a stream
            //string directoryName = destinationPath.Substring(0, destinationPath.Length - this.filename.Length);
            try {
                string directoryName = System.IO.Path.GetDirectoryName(destinationPath);//might throw System.IO.PathTooLongException
                //string directoryName = destinationPath.Substring(0, destinationPath.Length - System.IO.Path.GetFileName(destinationPath).Length);


                if (this.FileStreamType != FileStreamTypes.HttpPostMimeMultipartFormData && !System.IO.Directory.Exists(directoryName)) {
                    if (System.IO.File.Exists(directoryName)) {
                        ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error creating directory \"" + directoryName + "\" because a file with the same name already exists. Full path was : " + destinationPath);

                    }
                    else {
                        try {
                            System.IO.Directory.CreateDirectory(directoryName);
                        }
                        catch (Exception e) {
                            ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error creating directory \"" + directoryName + "\" for file : " + destinationPath + ".\n" + e.Message);
                        }
                    }
                }
                if (System.IO.File.Exists(destinationPath))
                    try {
                        System.IO.File.Delete(destinationPath);
                    }
                    catch (Exception e) {
                        this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error deleting file \"" + destinationPath + "\" (tried to replace it)");
                    }

                //do some special fixes such as un-chunk data or decompress compressed data (or base64 decode?)
                if (this.FileStreamType == FileStreamTypes.HttpGetChunked || (ParentAssemblerList.DecompressGzipStreams && this.contentEncoding == Packets.HttpPacket.ContentEncodings.Gzip) || this.contentEncoding == Packets.HttpPacket.ContentEncodings.Deflate) {
                    this.fileStream.Position = 0;//move to fileStream start since it needs to be read

                    if (this.FileStreamType == FileStreamTypes.HttpGetChunked && (ParentAssemblerList.DecompressGzipStreams && this.contentEncoding == Packets.HttpPacket.ContentEncodings.Gzip)) {
                        using (DeChunkedDataStream deChunkedStream = new DeChunkedDataStream(this.fileStream)) {
                            using (System.IO.Compression.GZipStream decompressedStream = new System.IO.Compression.GZipStream(deChunkedStream, System.IO.Compression.CompressionMode.Decompress)) {
                                try {
                                    this.WriteStreamToFile(decompressedStream, destinationPath, true);
                                }
                                catch (System.UnauthorizedAccessException) {
                                    this.ParentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                                }
                                catch (Exception e) {
                                    this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file " + destinationPath + " (" + e.Message + ")");
                                }
                                decompressedStream.Close();
                            }
                            deChunkedStream.Close();
                        }
                    }
                    else if (this.FileStreamType == FileStreamTypes.HttpGetChunked && this.contentEncoding == Packets.HttpPacket.ContentEncodings.Deflate) {
                        using (DeChunkedDataStream deChunkedStream = new DeChunkedDataStream(this.fileStream)) {
                            using (System.IO.Compression.DeflateStream decompressedStream = new System.IO.Compression.DeflateStream(deChunkedStream, System.IO.Compression.CompressionMode.Decompress)) {
                                try {
                                    this.WriteStreamToFile(decompressedStream, destinationPath, true);
                                }
                                catch (System.UnauthorizedAccessException) {
                                    this.ParentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                                }
                                catch (Exception e) {
                                    this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file " + destinationPath + " (" + e.Message + ")");
                                }

                                decompressedStream.Close();
                            }
                            deChunkedStream.Close();
                        }
                    }
                    else if (this.FileStreamType == FileStreamTypes.HttpGetChunked) {
                        using (DeChunkedDataStream deChunkedStream = new DeChunkedDataStream(this.fileStream)) {
                            try {
                                this.WriteStreamToFile(deChunkedStream, destinationPath, true);
                            }
                            catch (System.UnauthorizedAccessException) {
                                this.ParentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                            }
                            catch (Exception e) {
                                this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file " + destinationPath + " (" + e.Message + ")");
                            }
                            deChunkedStream.Close();
                        }
                    }
                    else {
                        using (System.IO.Compression.GZipStream decompressedStream = new System.IO.Compression.GZipStream(this.fileStream, System.IO.Compression.CompressionMode.Decompress)) {
                            try {
                                this.WriteStreamToFile(decompressedStream, destinationPath, true);
                            }
                            catch (System.UnauthorizedAccessException) {
                                this.ParentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                            }
                            catch (Exception e) {
                                this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file " + destinationPath + " (" + e.Message + ")");
                            }
                            decompressedStream.Close();
                        }
                    }

                    this.fileStream.Close();
                    System.IO.File.Delete(this.GetFilePath(FileAssmeblyRootLocation.cache).absolutPath);//delete the temp file

                }
                else if (this.FileStreamType == FileStreamTypes.HttpPostMimeMultipartFormData) {
                    Mime.UnbufferedReader mimeReader = new PacketParser.Mime.UnbufferedReader(this.fileStream);

                    List<Mime.MultipartPart> parts = new List<PacketParser.Mime.MultipartPart>();
                    if (!string.IsNullOrEmpty(this.MimeBoundary)) {
                        foreach (Mime.MultipartPart part in Mime.PartBuilder.GetParts(mimeReader, this.MimeBoundary)) {
                            parts.Add(part);
                        }
                    }
                    else {//TODO: Remove this else section
                        foreach (Mime.MultipartPart part in Mime.PartBuilder.GetParts(mimeReader, this.Details)) {
                            parts.Add(part);
                        }
                    }


                    this.ParentAssemblerList.PacketHandler.ExtractMultipartFormData(parts, this.FiveTuple, this.TransferIsClientToServer, Timestamp, this.InitialFrameNumber, ApplicationLayerProtocol.Unknown);

                    foreach (Mime.MultipartPart part in parts) {
                        if (part.Attributes["filename"] != null && part.Attributes["filename"].Length > 0 && part.Data != null && part.Data.Length > 0) {
                            //we have a file!
                            string mimeFileLocation = "/";
                            if (part.Attributes["filename"].IndexOfAny(DIRECTORY_SEPARATORS) >= 0) {
                                mimeFileLocation = part.Attributes["filename"];

                                foreach (char separator in DIRECTORY_SEPARATORS) {
                                    if (mimeFileLocation.Contains("" + separator))
                                        mimeFileLocation = mimeFileLocation.Substring(0, mimeFileLocation.LastIndexOf(separator));
                                }
                            }

                            string mimeFileName = part.Attributes["filename"];
                            foreach (char separator in DIRECTORY_SEPARATORS) {
                                if (mimeFileName.Contains("" + separator) && mimeFileName.Length > mimeFileName.LastIndexOf(separator) + 1)
                                    mimeFileName = mimeFileName.Substring(mimeFileName.LastIndexOf(separator) + 1);
                            }
                            using (FileStreamAssembler partAssembler = new FileStreamAssembler(this.ParentAssemblerList, this.FiveTuple, this.TransferIsClientToServer, FileStreamTypes.HttpPostMimeFileData, mimeFileName, mimeFileLocation, part.Attributes["filename"] + " in POST to " + this.Details, this.InitialFrameNumber, this.Timestamp)) {
                                this.ParentAssemblerList.Add(partAssembler);
                                partAssembler.FileContentLength = part.Data.Length;
                                partAssembler.FileSegmentRemainingBytes = part.Data.Length;
                                if (partAssembler.TryActivate()) {
                                    partAssembler.AddData(part.Data, 0);
                                }
                            }
                        }
                    }
                    this.fileStream.Close();
                    System.IO.File.Delete(this.GetFilePath(FileAssmeblyRootLocation.cache).absolutPath);
                }
                else if (this.contentEncoding == Packets.HttpPacket.ContentEncodings.Base64) {
                    this.fileStream.Position = 0;//move to fileStream start since it needs to be read
                    using (Base64DecodedStream base64DecodedStream = new Base64DecodedStream(this.fileStream)) {
                        try {
                            this.WriteStreamToFile(base64DecodedStream, destinationPath, true);
                        }
                        catch (System.UnauthorizedAccessException) {
                            this.ParentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                        }
                        catch (Exception e) {
                            this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file " + destinationPath + " (" + e.Message + ")");
                        }
                        base64DecodedStream.Close();
                    }
                    this.fileStream.Close();
                    System.IO.File.Delete(this.GetFilePath(FileAssmeblyRootLocation.cache).absolutPath);//delete the temp file
                }
                else {//files which are already completed can simply be moved to their final destination
                    this.fileStream?.Close();
                    try {
                        string tmpPath = this.GetFilePath(FileAssmeblyRootLocation.cache).absolutPath;
                        if (System.IO.File.Exists(tmpPath))
                            System.IO.File.Move(tmpPath, destinationPath);
                    }
                    catch (Exception e) {
                        this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error moving file \"" + GetFilePath(FileAssmeblyRootLocation.cache) + "\" to \"" + destinationPath + "\". " + e.Message);
                    }
                }
                if (System.IO.File.Exists(destinationPath)) {
                    if (ReconstructedFile.TryGetReconstructedFile(out ReconstructedFile completedFile, destinationPath, destinationRelativeUri, this.FiveTuple, this.TransferIsClientToServer, FileStreamType, Details, this.InitialFrameNumber, this.Timestamp, this.serverHostname, this.ExtensionFromHeader)) {
                        try {

                            //only report on partial files (from range requests) if settings say so
                            if (this.ParentAssemblerList.PacketHandler.ExtractPartialDownloads || this.ContentRange == null || completedFile.FileSize == this.ContentRange.Total) {
                                this.ParentAssemblerList.PacketHandler.AddReconstructedFile(completedFile);
                                this.FileReconstructed?.Invoke(this.extendedFileId, completedFile);

                                if (this.ParentAssemblerList.PacketHandler.FileCarvers.ContainsKey(completedFile.FileStreamType)) {
                                    foreach (var (extension, startPosition, length) in this.ParentAssemblerList.PacketHandler.FileCarvers[completedFile.FileStreamType].GetCarvedFileIndices(completedFile.FilePath)) {
                                        //ReconstructedFile carvedFile;
                                        using (var inFile = System.IO.File.OpenRead(completedFile.FilePath)) {
                                            string carvedPath = completedFile.FilePath + "." + extension;
                                            using (var outFile = System.IO.File.OpenWrite(carvedPath)) {
                                                inFile.Position = startPosition;
                                                if (startPosition + length < inFile.Length) {
                                                    byte[] buffer = new byte[16 * 1024];
                                                    int read;
                                                    long bytesWritten = 0;
                                                    while ((read = inFile.Read(buffer, 0, buffer.Length)) > 0) {
                                                        if (bytesWritten + read >= length) {
                                                            outFile.Write(buffer, 0, (int)(length - bytesWritten));
                                                            break;
                                                        }
                                                        outFile.Write(buffer, 0, read);
                                                        bytesWritten += read;
                                                    }
                                                }
                                                else {
                                                    inFile.CopyTo(outFile);
                                                }
                                                if (ReconstructedFile.TryGetReconstructedFile(out ReconstructedFile carvedFile, carvedPath, completedFile.RelativeUri, completedFile.FiveTuple, completedFile.TransferIsClientToServer, completedFile.FileStreamType, completedFile.Details, completedFile.InitialFrameNumber, completedFile.Timestamp, completedFile.ServerHostname, this.ExtensionFromHeader)) {
                                                    this.ParentAssemblerList.PacketHandler.AddReconstructedFile(carvedFile);
                                                    this.FileReconstructed?.Invoke(this.extendedFileId, carvedFile);
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            //reassemble file from HTTP range replies like "HTTP/1.1 206 Partial Content"
                            if (this.ContentRange != null) {

                                //this code is also in FileSegmentAssembler

                                string fileKey;
                                if (this.Details == null || this.Details.Length == 0)
                                    fileKey = this.SourceHost.IPAddress.ToString() + "|" + this.ContentRange.Total.ToString();
                                else
                                    fileKey = this.Details + "|" + this.ContentRange.Total.ToString();
                                PartialFileAssembler partialFileAssembler;
                                if (this.ParentAssemblerList.PartialFileAssemblerList.ContainsKey(fileKey))
                                    partialFileAssembler = this.ParentAssemblerList.PartialFileAssemblerList[fileKey];
                                else {
                                    partialFileAssembler = new PartialFileAssembler(fileAssmeblyRootLocation, this.FiveTuple, this.TransferIsClientToServer, this.FileStreamType, this.fileLocation, this.filename, this.ParentAssemblerList, this.Details, ContentRange.Total, this.InitialFrameNumber, this.serverHostname);
                                    this.ParentAssemblerList.PartialFileAssemblerList.Add(fileKey, partialFileAssembler);
                                }

                                partialFileAssembler.AddFile(completedFile, this.ContentRange);

                                if (partialFileAssembler.IsComplete()) {
                                    ReconstructedFile reconstructedFile = partialFileAssembler.Reassemble();
                                    this.ParentAssemblerList.PartialFileAssemblerList.Remove(fileKey);
                                    if (reconstructedFile != null) {
                                        this.ParentAssemblerList.PacketHandler.AddReconstructedFile(reconstructedFile);
                                        this.FileReconstructed?.Invoke(this.extendedFileId, reconstructedFile);
                                    }
                                }
                            }

                        }
                        catch (Exception e) {
                            this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error creating reconstructed file: " + e.Message);
                        }
                    }
                }
            }
            catch (System.IO.PathTooLongException e) {
                this.ParentAssemblerList.PacketHandler.OnAnomalyDetected("Error writing file to " + destinationPath + "(" + e.Message + ")");
            }
        }


        //this one might generate exceptions that need to be catched further up in the hierarchy!!!
        internal void WriteStreamToFile(System.IO.Stream stream, string destinationPath, bool setExtensionFromStreamHeader) {
            
            byte[] buffer = new byte[16 * 1024];
            int bytesRead = stream.Read(buffer, 0, buffer.Length);
            if(setExtensionFromStreamHeader && bytesRead > 7) {
                byte[] fileHeaderData = buffer.Take(Math.Min(bytesRead, 1024)).ToArray();
                //SetExtensionFromFileHeader(fileHeaderData, ref this.filename, ref destinationPath)
                this.ExtensionFromHeader = GetExtensionFromHeader(fileHeaderData);
            }
            using (System.IO.FileStream outputFile = new System.IO.FileStream(destinationPath, System.IO.FileMode.Create)) {
                while (bytesRead > 0) {
                    outputFile.Write(buffer, 0, bytesRead);
                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                }
                //outputFile.Close();
            }
        }

        /// <summary>
        /// Removes the data in the buffer, closes the file stream and deletes the temporary file.
        /// But the assembler is not removed from the parentAssemblerList!
        /// </summary>
        internal void Clear() {
            this.tcpPacketBufferWindow.Clear();
            if (this.fileStream != null) {
                this.fileStream.Close();
                if (System.IO.File.Exists(this.fileStream.Name))
                    System.IO.File.Delete(this.fileStream.Name);

                this.fileStream = null;
            }
        }

        internal class Base64DecodedStream : System.IO.Stream, IDisposable {

            private System.IO.Stream encodedStream;
            public override bool CanRead {
                get { return true; }
            }

            public override bool CanSeek {
                get { return false; }
            }

            public override bool CanWrite {
                get { return false; }
            }

            public override long Length {
                get {
                    throw new NotImplementedException();
                }
            }

            public override long Position {
                get {
                    throw new NotImplementedException();
                }

                set {
                    throw new NotImplementedException();
                }
            }

            public Base64DecodedStream(System.IO.Stream encodedStream) {
                this.encodedStream = encodedStream;
            }

            public override void Flush() {
                throw new NotImplementedException();
            }

            public override int Read(byte[] buffer, int offset, int count) {
                //1, 2 or 3 bytes raw => 4 bytes in base64
                //4, 5 or 6 bytes raw => 8 bytes in base64
                int encodedReadCount = (count / 3) * 4;//4 chars of base64 = 24 bits = 3 bytes raw
                if (count > 0 && encodedReadCount < 4)
                    encodedReadCount = 4;
                byte[] encodedBuffer = new byte[encodedReadCount];
                int encodedBytesRead = this.encodedStream.Read(encodedBuffer, 0, encodedReadCount);
                string base64String = ASCIIEncoding.ASCII.GetString(encodedBuffer, 0, encodedBytesRead);
                byte[] decoded = Convert.FromBase64String(base64String);
                Array.Copy(decoded, 0, buffer, offset, decoded.Length);
                return decoded.Length;
            }

            public override long Seek(long offset, SeekOrigin origin) {
                throw new NotImplementedException();
            }

            public override void SetLength(long value) {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count) {
                throw new NotImplementedException();
            }

            public new void Dispose() {
                this.encodedStream.Dispose();
                base.Dispose();
            }
        }

        internal class DeChunkedDataStream : System.IO.Stream, IDisposable {
            //private int position;//should be long
            private System.IO.Stream chunkedStream;
            private int currentChunkSize;
            private int readBytesInCurrentChunk;

            public override bool CanRead {
                get { return true; }
            }

            public override bool CanSeek {
                get { return false; }
            }

            public override bool CanWrite {
                get { return false; }
            }

            public override void Flush() {
                throw new Exception("The method or operation is not implemented.");
            }

            public override long Length {
                get { throw new Exception("The method or operation is not implemented."); }
            }

            public override long Position {
                get {
                    throw new Exception("The method or operation is not implemented.");
                }
                set {
                    throw new Exception("The method or operation is not implemented.");
                }
            }

            public DeChunkedDataStream(System.IO.Stream chunkedStream) {
                this.chunkedStream = chunkedStream;
                //this.position=0;//should be long
                this.currentChunkSize = 0;
                this.readBytesInCurrentChunk = 0;
            }

            public override int Read(byte[] buffer, int offset, int count) {
                int bytesRead = 0;
                if (this.readBytesInCurrentChunk >= this.currentChunkSize) {//I need to read a new chunk
                    StringBuilder chunkSizeString = new StringBuilder();//chunk-size as hex-string
                    while (true) {
                        int ib = chunkedStream.ReadByte();
                        if (ib < 0)//end of stream
                            return 0;

                        byte b = (byte)ib;
                        if (b != 0x0d) {
                            char c = (char)b;
                            string hexCharacters = "0123456789abcdefABCDEF";

                            if (hexCharacters.Contains("" + c))
                                chunkSizeString.Append((char)b);
                        }
                        else {
                            chunkedStream.ReadByte();//this should be the 0x0a that follows the 0x0d
                            if (chunkSizeString.Length > 0)//there are sometimes CRLF before the chunk-size value
                                break;
                        }
                    }
                    if (chunkSizeString.ToString().Length == 0)
                        this.currentChunkSize = 0;//I'm not sure if this line should really be needed...
                    else
                        this.currentChunkSize = Convert.ToInt32(chunkSizeString.ToString(), 16);
                    this.readBytesInCurrentChunk = 0;

                    if (this.currentChunkSize == 0)//end of chunk-stream
                        return 0;
                }

                bytesRead = this.chunkedStream.Read(buffer, offset, Math.Min(count, this.currentChunkSize - this.readBytesInCurrentChunk));
                this.readBytesInCurrentChunk += bytesRead;

                //see if I have to start reading the next chunk as well....
                if (bytesRead < count && this.readBytesInCurrentChunk == this.currentChunkSize) {
                    //we are at the end of the chunk
                    return bytesRead + this.Read(buffer, offset + bytesRead, count - bytesRead);//nice recursive stuff
                }
                else
                    return bytesRead;
            }

            public override long Seek(long offset, System.IO.SeekOrigin origin) {
                throw new Exception("The method or operation is not implemented.");
            }

            public override void SetLength(long value) {
                throw new Exception("The method or operation is not implemented.");
            }

            public override void Write(byte[] buffer, int offset, int count) {
                throw new Exception("The method or operation is not implemented.");
            }

            #region IDisposable Members

            public new void Dispose() {
                //throw new Exception("The method or operation is not implemented.");
                if (this.chunkedStream != null) {
                    this.chunkedStream.Close();
                    this.chunkedStream = null;
                }

                base.Dispose();
            }

            #endregion
        }

        #region IDisposable Members

        public void Dispose() {
            //throw new Exception("The method or operation is not implemented.");
            if (this.fileStream != null) {
                this.fileStream.Close();
                this.fileStream = null;
            }
        }

        #endregion
    }
}
