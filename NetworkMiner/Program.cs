//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using SharedUtils;
using System;
using System.Reflection;
using System.Diagnostics;
using System.Globalization;

namespace NetworkMiner {
    public static class Program {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main(string[] args) {
            // first set up the logger
            SetupLogger("NetworkMiner");


        }

        public static void SetupLogger(string applicationName) {

            Logger.ApplicationName = applicationName;

            foreach (string arg in Environment.GetCommandLineArgs()) {
                if (arg.Equals("--debug", StringComparison.InvariantCultureIgnoreCase)) {
                    Logger.CurrentLogLevel = Logger.LogLevel.Debug;
                    Logger.LogToConsole = true;
                }
                else if (arg.Equals("--eventlog", StringComparison.InvariantCultureIgnoreCase)) {
                    EventLog applicationEventLog = new EventLog("Application");
                    applicationEventLog.Source = applicationName;

                    Logger.CurrentLogLevel = Logger.LogLevel.Debug;
                    Logger.EnableEventLog((message, eventLogEntryType) => applicationEventLog.WriteEntry(message, (EventLogEntryType)eventLogEntryType));
                }
                else if (arg.Equals("--filelog", StringComparison.InvariantCultureIgnoreCase)) {
                    Logger.CurrentLogLevel = Logger.LogLevel.Debug;
                    Logger.LogToFile = true;
                }
            }
#if DEBUG
            Logger.CurrentLogLevel = Logger.LogLevel.Debug;
            Logger.LogToConsole = true;
            Logger.LogToFile = true;
#endif

            String executablePath = Assembly.GetEntryAssembly().Location;
            FileVersionInfo productInfo = FileVersionInfo.GetVersionInfo(executablePath);
            Logger.Log("Environment.Is64BitOperatingSystem = " + Environment.Is64BitOperatingSystem.ToString(), Logger.EventLogEntryType.Information);
            Logger.Log("Environment.Is64BitProcess = " + Environment.Is64BitProcess.ToString(), Logger.EventLogEntryType.Information);
            Logger.Log(productInfo.ProductName + " " + productInfo.ProductVersion, Logger.EventLogEntryType.Information);
            Logger.Log("Application.ExecutablePath = " + executablePath, Logger.EventLogEntryType.Information);
            Logger.Log("Application.CurrentCulture = " + CultureInfo.CurrentCulture, Logger.EventLogEntryType.Information);
            Logger.Log("Environment.Version = " + Environment.Version, Logger.EventLogEntryType.Information);//4.0.30319.42000 =  .NET Framework 4.6, its point releases, and the .NET Framework 4.7
            Logger.Log("Setting up application rendering", Logger.EventLogEntryType.Information);

        }
    }
}