using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using System.IO.IsolatedStorage;

namespace SharedUtils {
    public static class Logger {

        //rfc3164
        public enum SyslogSeverity : byte {
            Emergency = 0,
            Alert = 1,
            Critical = 2,
            Error = 3,
            Warning = 4,
            Notice = 5,
            Informational = 6,
            Debug = 7
        }

        //rfc3164
        public enum SyslogFacility : byte {
            kernel = 0,
            user = 1,
            mail = 2,
            system_deamon = 3,
            security_authorization = 4,
            syslogd_internal = 5,
            line_printer = 6,
            network_news = 7,
            UUCP = 8,
            clock = 9,
            security_authorization_2 = 10,
            FTP = 11,
            NTP = 12,
            log_audit = 13,
            log_alert = 14,
            clock_daemon = 15,
            local0 = 16,
            local1 = 17,
            local2 = 18,
            local3 = 19,
            local4 = 20,
            local5 = 21,
            local6 = 22,
            local7 = 23
        }

        public static int GetSyslogPriority(SyslogFacility facility, SyslogSeverity severity) {
            return ((byte)facility * 8) + (byte)severity;
        }

        public static int GetSyslogPriority(EventLogEntryType eventLogType) {
            if (eventLogType == EventLogEntryType.Error)
                return GetSyslogPriority(SyslogFacility.log_alert, SyslogSeverity.Error);
            else if (eventLogType == EventLogEntryType.Warning)
                return GetSyslogPriority(SyslogFacility.log_audit, SyslogSeverity.Warning);
            else if (eventLogType == EventLogEntryType.Information)
                return GetSyslogPriority(SyslogFacility.log_audit, SyslogSeverity.Informational);
            else
                return GetSyslogPriority(SyslogFacility.log_audit, SyslogSeverity.Informational);
        }

        public static byte GetSyslogSeverity(EventLogEntryType eventLogType) {
            if (eventLogType == EventLogEntryType.Error)
                return (byte)SyslogSeverity.Error;
            else if (eventLogType == EventLogEntryType.Warning)
                return (byte)SyslogSeverity.Warning;
            else if (eventLogType == EventLogEntryType.Information)
                return (byte)SyslogSeverity.Informational;
            else
                return (byte)SyslogSeverity.Informational;
        }

        /// <summary>
        /// Selected log-level.
        /// "Normal" log level writes log entries to the Windows Event Log when there are errors.
        /// "Debug" also writes debug messages to disk. The path for this log file can be found in an Event Log entry
        /// </summary>
        public enum LogLevel { Normal, Debug };

        public enum EventLogEntryType {
            /// <summary>An error event. This indicates a significant problem the user should know about; usually a loss of functionality or data.</summary>
            // Token: 0x0400270B RID: 9995
            Error = 1,
            /// <summary>A warning event. This indicates a problem that is not immediately significant, but that may signify conditions that could cause future problems.</summary>
            // Token: 0x0400270C RID: 9996
            Warning,
            /// <summary>An information event. This indicates a significant, successful operation.</summary>
            // Token: 0x0400270D RID: 9997
            Information = 4,
            /// <summary>A success audit event. This indicates a security event that occurs when an audited access attempt is successful; for example, logging on successfully.</summary>
            // Token: 0x0400270E RID: 9998
            SuccessAudit = 8,
            /// <summary>A failure audit event. This indicates a security event that occurs when an audited access attempt fails; for example, a failed attempt to open a file.</summary>
            // Token: 0x0400270F RID: 9999
            FailureAudit = 16
        }

        private static readonly System.Threading.SemaphoreSlim consoleOutLock = new System.Threading.SemaphoreSlim(1, 1);
        private static readonly System.Threading.SemaphoreSlim consoleErrorLock = new System.Threading.SemaphoreSlim(1, 1);
        public static LogLevel CurrentLogLevel = LogLevel.Normal;
        public static bool PrependTimestampInConsoleLog = true;
        public static bool PrependSyslogPriorityInConsoleLog = false;
        public static bool RedirectStdOutToStdErr = false;
        public static bool LogToConsole = false;
        private static bool logToEventLog = false;
        public static bool LogToFile = false;
        public static string ApplicationName = null;

        private static string logStartTimestampString = DateTime.Now.ToString("yyMMdd-HHmmss");

        //private static object logFileLock = new object();
        private static readonly System.Threading.SemaphoreSlim logFileLock = new System.Threading.SemaphoreSlim(1, 1);
        private static int debugLogEventCount = 0;
        //private static System.Diagnostics.EventLog applicationEventLog = null;
        private static Action<string, EventLogEntryType> eventLogWriteEntryAction = null;
        public static string LogFilePath = String.Empty;

        public static IsolatedStorageFile GetIsolatedStorageFile() {
            return IsolatedStorageFile.GetStore(IsolatedStorageScope.Assembly | IsolatedStorageScope.User, null, null);
        }


        public static void EnableEventLog(Action<string, EventLogEntryType> eventLogWriteEntry) {
            eventLogWriteEntryAction = eventLogWriteEntry;
            /*
            applicationEventLog = new System.Diagnostics.EventLog("Application");
            if(ApplicationName == null)
                applicationEventLog.Source = "Application";
            else
                applicationEventLog.Source = ApplicationName;
            */
            logToEventLog = true;
        }

        public static void Log(string message, EventLogEntryType eventLogEntryType, bool forceLog = false) {
            if(eventLogEntryType == EventLogEntryType.Error) {
                try {
                    StdErrLog(message, eventLogEntryType);
                }
                catch { }
                if (eventLogWriteEntryAction != null) {
                    try {
                        //eventLog(message, eventLogEntryType);
                        eventLogWriteEntryAction(message, eventLogEntryType);
                    }
                    catch { }
                }
                try {
                    fileLog(message, eventLogEntryType.ToString());
                }
                catch { }
            }
            else if (CurrentLogLevel == LogLevel.Debug || forceLog) {
                if (LogToConsole) {
                    if (RedirectStdOutToStdErr)
                        StdErrLog(message, eventLogEntryType);
                    else
                        ConsoleLog(message, eventLogEntryType);
                }
                if (logToEventLog && eventLogWriteEntryAction != null)
                    eventLogWriteEntryAction(message, eventLogEntryType);
                if (LogToFile)
                    fileLog(message, eventLogEntryType.ToString());
            }
            
        }

        public static async System.Threading.Tasks.Task LogAsync(string message, EventLogEntryType eventLogEntryType, bool forceLog = false) {
            if (eventLogEntryType == EventLogEntryType.Error) {
                try {
                    //await ConsoleLogAsync(message, eventLogEntryType);
                    await StdErrLogAsync(message, eventLogEntryType);
                }
                catch { }
                if (eventLogWriteEntryAction != null) {
                    try {
                        //eventLogWriteEntryAction(message, eventLogEntryType);
                        await System.Threading.Tasks.Task.Run(() => eventLogWriteEntryAction(message, eventLogEntryType));
                    }
                    catch { }
                }
                try {
                    await fileLogAsync(message, eventLogEntryType.ToString());
                }
                catch { }
            }
            else if (CurrentLogLevel == LogLevel.Debug || forceLog) {
                if (LogToConsole) {
                    if (RedirectStdOutToStdErr)
                        await StdErrLogAsync(message, eventLogEntryType);
                    else
                        await ConsoleLogAsync(message, eventLogEntryType);
                }
                if (logToEventLog && eventLogWriteEntryAction != null)
                    await System.Threading.Tasks.Task.Run(() => eventLogWriteEntryAction(message, eventLogEntryType));
                if (LogToFile)
                    await fileLogAsync(message, eventLogEntryType.ToString());
            }

        }

        /*
        private static void eventLog(string message, EventLogEntryType eventLogEntryType) {

            if (eventLogWriteEntryAction != null)
                eventLogWriteEntryAction(message, eventLogEntryType);
            else
                System.Diagnostics.EventLog.WriteEntry("Application", message, eventLogEntryType);
            
        }
        */

        private static string GetConsoleLogString(string message, EventLogEntryType eventLogEntryType) {
            StringBuilder sb = new StringBuilder();
            if (PrependSyslogPriorityInConsoleLog)
                sb.Append("<" + GetSyslogSeverity(eventLogEntryType) + ">");
            if(PrependTimestampInConsoleLog)
                sb.Append(DateTime.Now.ToString("o", System.Globalization.CultureInfo.InvariantCulture) + " ");
            sb.Append(message);
            return sb.ToString();
        }

        public static void ConsoleLog(string message, EventLogEntryType eventLogEntryType = EventLogEntryType.Information) {
            consoleOutLock.Wait();
            try {
                System.Console.Out.WriteLine(GetConsoleLogString(message, eventLogEntryType));
            }
            finally {
                consoleOutLock.Release();
            }
        }

        public static async System.Threading.Tasks.Task ConsoleLogAsync(string message, EventLogEntryType eventLogEntryType) {
            await consoleOutLock.WaitAsync();
            try {
                await System.Console.Out.WriteLineAsync(GetConsoleLogString(message, eventLogEntryType));
            }
            finally {
                consoleOutLock.Release();
            }
        }

        public static void StdErrLog(string message, EventLogEntryType eventLogEntryType = EventLogEntryType.Information) {
            consoleErrorLock.Wait();
            try {
                System.Console.Error.WriteLine(GetConsoleLogString(message, eventLogEntryType));
            }
            finally {
                consoleErrorLock.Release();
            }
        }

        public static async System.Threading.Tasks.Task StdErrLogAsync(string message, EventLogEntryType eventLogEntryType) {
            await consoleErrorLock.WaitAsync();
            try {
                await System.Console.Error.WriteLineAsync(GetConsoleLogString(message, eventLogEntryType));
            }
            finally {
                consoleErrorLock.Release();
            }
        }


        private static void fileLog(string message, string entryType = "DEBUG") {
            if (CurrentLogLevel == LogLevel.Debug) {

                using (IsolatedStorageFile isoFile = GetIsolatedStorageFile()) {
                    logFileLock.Wait();
                    try {
                        //IsolatedStorage will be something like: C:\WINDOWS\system32\config\systemprofile\AppData\Local\IsolatedStorage\arpzpldm.neh\4hq14imw.y2b\Publisher.5yo4swcgiijiq5te00ddqtmrsgfhvrp4\AssemFiles\
                        
                        using (IsolatedStorageFileStream stream = new IsolatedStorageFileStream(ApplicationName + "_" + logStartTimestampString + ".log", System.IO.FileMode.Append, System.IO.FileAccess.Write, System.IO.FileShare.Read, isoFile)) {
                            //stream.Seek(0, System.IO.SeekOrigin.End);

                            if (debugLogEventCount == 0) {
                                try {
                                    LogFilePath = stream.GetType().GetField("m_FullPath", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(stream).ToString();
                                    if (logToEventLog && eventLogWriteEntryAction != null)
                                        eventLogWriteEntryAction("Saving debug log to " + LogFilePath, EventLogEntryType.Information);
                                    else
                                        ConsoleLog("Saving debug log to " + LogFilePath);
                                }
                                catch { }
                            }
                            using (System.IO.StreamWriter writer = new System.IO.StreamWriter(stream)) {
                                writer.WriteLine(DateTime.UtcNow.ToString("s", System.Globalization.CultureInfo.InvariantCulture) + "\t[" + entryType + "]\t" + message);

                            }
                        }
                    }
                    catch (System.IO.IOException e) {
                        if (debugLogEventCount == 0 && eventLogWriteEntryAction != null)
                            eventLogWriteEntryAction(e.Message, EventLogEntryType.Error);
                    }
                    catch (System.NullReferenceException) {
                        LogToFile = false;
                    }
                    finally {
                        logFileLock.Release();
                        System.Threading.Interlocked.Increment(ref debugLogEventCount);
                    }

                }
                
            }
        }

        private static async System.Threading.Tasks.Task fileLogAsync(string message, string entryType = "DEBUG") {
            if (CurrentLogLevel == LogLevel.Debug) {

                using (IsolatedStorageFile isoFile = GetIsolatedStorageFile()) {
                    await logFileLock.WaitAsync();
                    try {
                        //IsolatedStorage will be something like: C:\WINDOWS\system32\config\systemprofile\AppData\Local\IsolatedStorage\arpzpldm.neh\4hq14imw.y2b\Publisher.5yo4swcgiijiq5te00ddqtmrsgfhvrp4\AssemFiles\
                        using (IsolatedStorageFileStream stream = new IsolatedStorageFileStream(ApplicationName + "_" + logStartTimestampString + ".log", System.IO.FileMode.Append, System.IO.FileAccess.Write, System.IO.FileShare.Read, isoFile)) {
                            //stream.Seek(0, System.IO.SeekOrigin.End);

                            if (debugLogEventCount == 0) {
                                try {
                                    string path = stream.GetType().GetField("m_FullPath", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).GetValue(stream).ToString();
                                    if (logToEventLog && eventLogWriteEntryAction != null)
                                        await System.Threading.Tasks.Task.Run(() => eventLogWriteEntryAction("Saving debug log to " + path, EventLogEntryType.Information));
                                    else
                                        await ConsoleLogAsync("Saving debug log to " + path, EventLogEntryType.Information);
                                }
                                catch { }
                            }
                            using (System.IO.StreamWriter writer = new System.IO.StreamWriter(stream)) {
                                await writer.WriteLineAsync(DateTime.UtcNow.ToString("s", System.Globalization.CultureInfo.InvariantCulture) + "\t[" + entryType + "]\t" + message);

                            }
                        }
                    }
                    catch (System.IO.IOException e) {
                        if (debugLogEventCount == 0 && eventLogWriteEntryAction != null)
                            await System.Threading.Tasks.Task.Run(() => eventLogWriteEntryAction(e.Message, EventLogEntryType.Error));
                    }
                    catch (System.NullReferenceException) {
                        LogToFile = false;
                    }
                    finally {
                        logFileLock.Release();
                        System.Threading.Interlocked.Increment(ref debugLogEventCount);
                    }

                }

            }
        }
    }
}
