using System;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Globalization;

using SharedUtils;


namespace NetworkMinerCLI {
    public class Program {

        public static readonly string EXE_PATH = Path.GetFullPath(Assembly.GetEntryAssembly().Location);

        public static void Main(string[] args) {
            // first set up the logger
            SetupLogger(Assembly.GetEntryAssembly().GetName().Name);

            // get the pcap file from the CLI arguments
            string[] parms = Environment.GetCommandLineArgs();
            string filename = null;
            if (parms.Length > 1) {
                filename = parms[parms.Length - 1];
            }

            NMCLI parser = new NMCLI(filename);
            parser.ParsePCAPFile();
        }

        private static void SetupLogger(string applicationName) {

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

        public static void PrintError(string errorMsg, int exitCode = 0) {
            Logger.Log(errorMsg, Logger.EventLogEntryType.Error);

            // exit the application if the exit code is set
            if (exitCode != 0)
                System.Environment.Exit(exitCode);
        }
    }
}
