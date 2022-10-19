using System;
using System.IO;

using PacketParser;
using SharedUtils;
using SharedUtils.Pcap;


namespace NetworkMinerCLI {
    public class NMCLI {

        private string pcapFilePath;

        public NMCLI(string pcapFilePath) {
            if (pcapFilePath != null) {
                if (! File.Exists(pcapFilePath)) {
                    Program.PrintError("The specified file '" + pcapFilePath + "' doesn't exist!", 2);
                } else if (Directory.Exists(pcapFilePath)) {
                    Program.PrintError("NetworkMiner can't open directories, try a PCAP file instead!", 3);
                }
            } else {
                Program.PrintError("No PCAP file specified!", 1);
            }

            this.pcapFilePath = pcapFilePath;
        }

        /// <summary>
        /// Funtion used to create a new PacketHandler
        /// </summary>
        /// <param name="outputDirectory"></param>
        private PacketHandler CreatePacketHandler(DirectoryInfo outputDirectory) {
            //make sure that folders exists
            try {
                // directory for the assembled files
                DirectoryInfo di = new DirectoryInfo(outputDirectory.FullName + Path.DirectorySeparatorChar + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY);
                if (!di.Exists)
                    di.Create();

                // cache directory
                di = new DirectoryInfo(outputDirectory.FullName + Path.DirectorySeparatorChar + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY + Path.DirectorySeparatorChar + "cache");
                if (!di.Exists)
                    di.Create();
            }
            catch (UnauthorizedAccessException ex) {
                Logger.Log(ex.Message, SharedUtils.Logger.EventLogEntryType.Error);
                Program.PrintError("Please ensure that the user has write permissions in the AssembledFiles and Captures directories.", 1);
            }

            PacketHandler packetHandler = new PacketHandler(
                // applicationExecutablePath
                Program.EXE_PATH,
                // outputPath
                outputDirectory.FullName,
                // preloadedFingerprints
                // NetworkMinerForm.cs -> default null
                null,
                // ignoreMissingFingerprintFiles
                // PacketHandlerWrapper.cs -> always false
                false,
                // toCustomTimeZoneStringFunction
                // GuiProperties.cs -> simplified
                new Func<DateTime, string>((DateTime dateTime) => { return dateTime.ToUniversalTime().ToString("u"); }),
                // useRelativePathIfAvailable
                // NetworkMinerForm.cs -> default true
                true,
                // verifyX509Certificates
                // NetworkMinerForm.cs -> default false
                false);
            packetHandler.StartBackgroundThreads();

            return packetHandler;
        }

        /// <summary>
        /// Funtion used to close an existing PacketHandler
        /// </summary>
        private void ClosePacketHandler(PacketHandler packetHandler) {
            // avoid exceptions
            if (packetHandler != null) {
                // stop the background threads
                packetHandler.AbortBackgroundThreads();

                // remove the cache directory
                DirectoryInfo di = new DirectoryInfo(packetHandler.OutputDirectory + Path.DirectorySeparatorChar + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY + Path.DirectorySeparatorChar + "cache");
                if (di.Exists)
                    di.Delete();
            }
        }

        private void ParsePCAPFile(String filePath, PacketHandler packetHandler) {
            int percentRead = 0;

            Logger.Log("Loading " + filePath, Logger.EventLogEntryType.Information);

            PcapFileReader pcapReader = null;
            try {
                using (pcapReader = new PcapFileReader(filePath)) {
                    DateTime parsingStartTime = DateTime.Now;
                    Logger.Log(filePath + " start parsing " + parsingStartTime.ToString(), Logger.EventLogEntryType.Information);
                    Console.WriteLine("Start parsing " + filePath);

                    int enqueuedFramesSinceLastWait = 0;

                    foreach (PcapFrame pcapPacket in pcapReader.PacketEnumerator()) {
                        try {
                            Frame frame = packetHandler.GetFrame(pcapPacket.Timestamp, pcapPacket.Data, pcapPacket.DataLinkType);
                            packetHandler.AddFrameToFrameParsingQueue(frame);
                            enqueuedFramesSinceLastWait++;
                            int newPercentRead = pcapReader.GetPercentRead(packetHandler.FramesToParseQueuedByteCount);
                            if (newPercentRead != percentRead) {
                                percentRead = newPercentRead;

                                // output percent
                                Console.WriteLine("Progress: " + percentRead + "%");
                            }
                        } catch (Exception frameException) {
                            Logger.Log(frameException.GetType().ToString() + " when reading frame: " + frameException.Message, Logger.EventLogEntryType.Error);
#if DEBUG
                            throw frameException;
#endif
                    }
                    }
                    Logger.Log(enqueuedFramesSinceLastWait + " frames read in " + DateTime.Now.Subtract(parsingStartTime).ToString(), Logger.EventLogEntryType.Information);

                    while (packetHandler.FramesInQueue > 0) {//just to make sure we dont finish too early
                        System.Threading.Thread.Sleep(200);

                        int newPercentRead = pcapReader.GetPercentRead(packetHandler.FramesToParseQueuedByteCount);
                        if (newPercentRead != percentRead) {
                            percentRead = newPercentRead;

                            // output percent
                            Console.WriteLine("Progress: " + percentRead + "%");
                        }
                    }
                    TimeSpan parsingTimeTotal = DateTime.Now.Subtract(parsingStartTime);
                    Logger.Log(filePath + " parsed in " + parsingTimeTotal.ToString(), Logger.EventLogEntryType.Information);
                    Console.WriteLine("Finished parsing " + filePath);
                }
            } catch (InvalidDataException ex) {
                    Logger.Log("LoadPcapFile1: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                    if (ex.Message.Contains("Magic number is A0D0D0A"))
                        Program.PrintError("This is a PcapNg file. NetworkMiner Professional is required to parse PcapNg files.\n\nNetworkMiner Professional can be purchased from Netresec's website:\nhttp://www.netresec.com/", 4);
                    else
                        Program.PrintError("Error opening PCAP file: " + ex.Message, 4);
                    if (pcapReader != null)
                        pcapReader.Dispose();
            } catch (UnauthorizedAccessException ex) {
                SharedUtils.Logger.Log("LoadPcapFile2: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                Program.PrintError("Unauthorized to open file " + filePath, 5);

                if (pcapReader != null)
                    pcapReader.Dispose();
            } catch (Exception ex) {
                SharedUtils.Logger.Log("LoadPcapFile3: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                Program.PrintError("Error opening PCAP file: " + ex.Message, 1);

                if (pcapReader != null)
                    pcapReader.Dispose();
            }
        }

        public void ParsePCAPFile() {
            // create the packet handler
            PacketHandler packetHandler = CreatePacketHandler(new DirectoryInfo(Path.GetDirectoryName(Program.EXE_PATH)));

            // parse the PCAP file
            ParsePCAPFile(this.pcapFilePath, packetHandler);

            // close packet handler
            ClosePacketHandler(packetHandler);
        }
    }
}
