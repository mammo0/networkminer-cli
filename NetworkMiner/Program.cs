//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using PacketParser;
using SharedUtils;
using SharedUtils.Pcap;
using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Globalization;

namespace NetworkMiner {
    public static class Program {

        private static readonly string EXE_PATH = Path.GetFullPath(Assembly.GetEntryAssembly().Location);

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main(string[] args) {
            // first set up the logger
            SetupLogger("NetworkMiner");

            // get the pcap file from the CLI arguments
            string[] parms = Environment.GetCommandLineArgs();
            string filename = null;
            if (parms.Length > 1) {
                filename = parms[parms.Length - 1];
                if (! File.Exists(filename)) {
                    PrintError("The specified file '" + filename + "' doesn't exist!", 2);
                } else if (Directory.Exists(filename)) {
                    PrintError("NetworkMiner can't open directories, try a PCAP file instead!", 3);
                }
            } else {
                PrintError("No PCAP file specified!", 1);
            }

            // create the packet handler
            PacketHandler packetHandler = CreatePacketHandler(new DirectoryInfo(Path.GetDirectoryName(EXE_PATH)));

            // parse the PCAP file
            ParsePCAPFile(filename, packetHandler);

            // close packet handler
            ClosePacketHandler(packetHandler);
        }


        public static void SetupLogger(string applicationName) {

            Logger.ApplicationName = applicationName;

            foreach (string arg in Environment.GetCommandLineArgs()) {
                if (arg.Equals("--debug", StringComparison.InvariantCultureIgnoreCase)) {
                    Logger.CurrentLogLevel = Logger.LogLevel.Debug;
                    Logger.LogToConsole = true;
                }
                else if (arg.Equals("--eventlog", StringComparison.InvariantCultureIgnoreCase)) {
                    System.Diagnostics.EventLog applicationEventLog = new System.Diagnostics.EventLog("Application");
                    applicationEventLog.Source = applicationName;

                    Logger.CurrentLogLevel = Logger.LogLevel.Debug;
                    Logger.EnableEventLog((message, eventLogEntryType) => applicationEventLog.WriteEntry(message, (System.Diagnostics.EventLogEntryType)eventLogEntryType));
                }
                else if (arg.Equals("--filelog", StringComparison.InvariantCultureIgnoreCase)) {
                    Logger.CurrentLogLevel = Logger.LogLevel.Debug;
                    Logger.LogToFile = true;
                }
            }
#if DEBUG
            Logger.CurrentLogLevel = Logger.LogLevel.Debug;
            Logger.LogToConsole = true;
            //Logger.EnableEventLog();
            Logger.LogToFile = true;
#endif

            FileVersionInfo productInfo = FileVersionInfo.GetVersionInfo(EXE_PATH);
            Logger.Log("Environment.Is64BitOperatingSystem = " + Environment.Is64BitOperatingSystem.ToString(), Logger.EventLogEntryType.Information);
            Logger.Log("Environment.Is64BitProcess = " + Environment.Is64BitProcess.ToString(), Logger.EventLogEntryType.Information);
            Logger.Log(productInfo.ProductName + " " + productInfo.ProductVersion, Logger.EventLogEntryType.Information);
            Logger.Log("Application.ExecutablePath = " + EXE_PATH, Logger.EventLogEntryType.Information);
            Logger.Log("Application.CurrentCulture = " + CultureInfo.CurrentCulture, Logger.EventLogEntryType.Information);
            Logger.Log("Environment.Version = " + Environment.Version, Logger.EventLogEntryType.Information);//4.0.30319.42000 =  .NET Framework 4.6, its point releases, and the .NET Framework 4.7
            Logger.Log("Starting application", Logger.EventLogEntryType.Information);

        }

        private static void PrintError(string errorMsg, int exitCode = 1) {
            Logger.Log(errorMsg, Logger.EventLogEntryType.Error);
            System.Environment.Exit(exitCode);
        }

        private static void ParsePCAPFile(String filePath, PacketHandler packetHandler) {
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
                        PrintError("This is a PcapNg file. NetworkMiner Professional is required to parse PcapNg files.\n\nNetworkMiner Professional can be purchased from Netresec's website:\nhttp://www.netresec.com/", 4);
                    else
                        PrintError("Error opening PCAP file: " + ex.Message, 4);
                    if (pcapReader != null)
                        pcapReader.Dispose();
            } catch (UnauthorizedAccessException ex) {
                SharedUtils.Logger.Log("LoadPcapFile2: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                PrintError("Unauthorized to open file " + filePath, 5);

                if (pcapReader != null)
                    pcapReader.Dispose();
            } catch (Exception ex) {
                SharedUtils.Logger.Log("LoadPcapFile3: " + ex.Message, SharedUtils.Logger.EventLogEntryType.Warning);

                PrintError("Error opening PCAP file: " + ex.Message, 1);

                if (pcapReader != null)
                    pcapReader.Dispose();
            }
        }

        /// <summary>
        /// Funtion used to create a new PacketHandler
        /// </summary>
        /// <param name="outputDirectory"></param>
        private static PacketHandler CreatePacketHandler(DirectoryInfo outputDirectory) {
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
                PrintError("Please ensure that the user has write permissions in the AssembledFiles and Captures directories.", 1);
            }

            PacketHandler packetHandler = new PacketHandler(
                // applicationExecutablePath
                EXE_PATH,
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
        private static void ClosePacketHandler(PacketHandler packetHandler) {
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
    }
}
