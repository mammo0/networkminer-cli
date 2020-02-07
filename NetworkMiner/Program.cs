//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Windows.Forms;

namespace NetworkMiner {
    public static class Program {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args) {

            SetupLogger("NetworkMiner");

            bool legacyGui = false;
            bool checkForUpdates = true;
            foreach (string arg in Environment.GetCommandLineArgs()) {
                if (arg.Equals("--legacygui", StringComparison.CurrentCultureIgnoreCase))
                    legacyGui = true;
                else if (arg.Equals("--noupdatecheck", StringComparison.CurrentCultureIgnoreCase))
                    checkForUpdates = false;
            }

            if(!legacyGui)
                Application.EnableVisualStyles();
            //Application.SetCompatibleTextRenderingDefault(false);//causes mono on OSX to hang?
            SharedUtils.Logger.Log("Starting the application", SharedUtils.Logger.EventLogEntryType.Information);

            try {
                NetworkMinerForm networkMinerForm = new NetworkMinerForm();
                if(checkForUpdates)
                    NetworkMiner.UpdateCheck.ShowNewVersionFormIfAvailableAsync(networkMinerForm, System.Reflection.Assembly.GetEntryAssembly().GetName().Version);
                else
                    SharedUtils.Logger.Log("Skipping update check", SharedUtils.Logger.EventLogEntryType.Information);
                SharedUtils.Logger.Log("GUI form object created, starting application message loop", SharedUtils.Logger.EventLogEntryType.Information);
                Application.Run(networkMinerForm);
            }
            
            catch (System.IO.FileNotFoundException e) {
                if (PacketParser.Utils.SystemHelper.IsRunningOnMono()) {
                    System.Text.StringBuilder sb = new System.Text.StringBuilder("Make sure you have installed the following Mono packages: ");
                    foreach (string p in NetworkMinerForm.RecommendedMonoPackages) {
                        sb.Append(p);
                        sb.Append(" ");
                    }
                    sb.Append(Environment.NewLine);
                    SharedUtils.Logger.ConsoleLog(sb.ToString());
                }
                SharedUtils.Logger.Log("Error creating NetworkMiner GUI Form: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
#if DEBUG
                throw e;
#else
                return;
#endif
            }
#if !DEBUG
            catch (Exception e) {
                if (e is System.TypeLoadException tle && PacketParser.Utils.SystemHelper.IsRunningOnMono()) {
                    SharedUtils.Logger.Log("System.TypeLoadException when starting NetworkMiner: " + tle.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    MessageBox.Show("Mono version 5.4 or later is required to run NetworkMiner 2.5 or later.", "Unable to start NetworkMiner", MessageBoxButtons.OK, MessageBoxIcon.Error);

                }
                else {
                    SharedUtils.Logger.Log("Unable to start NetworkMiner: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                    MessageBox.Show(e.Message, "Unable to start NetworkMiner", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                if(e is NullReferenceException)
                {
                    SharedUtils.Logger.Log(e.GetType().ToString() + " : " + e.StackTrace, SharedUtils.Logger.EventLogEntryType.Information);
                }
            }
#endif


        }

        public static void SetupLogger(string applicationName) {

            SharedUtils.Logger.ApplicationName = applicationName;

            foreach (string arg in Environment.GetCommandLineArgs()) {
                if (arg.Equals("--debug", StringComparison.InvariantCultureIgnoreCase)) {
                    SharedUtils.Logger.CurrentLogLevel = SharedUtils.Logger.LogLevel.Debug;
                    SharedUtils.Logger.LogToConsole = true;
                }
                else if (arg.Equals("--eventlog", StringComparison.InvariantCultureIgnoreCase)) {
                    System.Diagnostics.EventLog applicationEventLog = new System.Diagnostics.EventLog("Application");
                    applicationEventLog.Source = applicationName;

                    SharedUtils.Logger.CurrentLogLevel = SharedUtils.Logger.LogLevel.Debug;
                    SharedUtils.Logger.EnableEventLog((message, eventLogEntryType) => applicationEventLog.WriteEntry(message, (System.Diagnostics.EventLogEntryType)eventLogEntryType));
                }
                else if (arg.Equals("--filelog", StringComparison.InvariantCultureIgnoreCase)) {
                    SharedUtils.Logger.CurrentLogLevel = SharedUtils.Logger.LogLevel.Debug;
                    SharedUtils.Logger.LogToFile = true;
                }
            }
#if DEBUG
            SharedUtils.Logger.CurrentLogLevel = SharedUtils.Logger.LogLevel.Debug;
            SharedUtils.Logger.LogToConsole = true;
            //SharedUtils.Logger.EnableEventLog();
            SharedUtils.Logger.LogToFile = true;
#endif

            
            SharedUtils.Logger.Log("Environment.Is64BitOperatingSystem = " + Environment.Is64BitOperatingSystem.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
            SharedUtils.Logger.Log("Environment.Is64BitProcess = " + Environment.Is64BitProcess.ToString(), SharedUtils.Logger.EventLogEntryType.Information);
            SharedUtils.Logger.Log(Application.ProductName + " " + Application.ProductVersion, SharedUtils.Logger.EventLogEntryType.Information);
            SharedUtils.Logger.Log("Application.ExecutablePath = " + Application.ExecutablePath, SharedUtils.Logger.EventLogEntryType.Information);
            SharedUtils.Logger.Log("Application.CurrentCulture = " + Application.CurrentCulture, SharedUtils.Logger.EventLogEntryType.Information);
            SharedUtils.Logger.Log("Environment.Version = " + Environment.Version, SharedUtils.Logger.EventLogEntryType.Information);//4.0.30319.42000 =  .NET Framework 4.6, its point releases, and the .NET Framework 4.7
            SharedUtils.Logger.Log("Setting up application rendering", SharedUtils.Logger.EventLogEntryType.Information);

        }
    }
}