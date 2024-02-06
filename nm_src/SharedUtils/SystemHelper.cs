using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharedUtils {
    public class SystemHelper {

        public static bool IsRunningOnMono() {
            return Type.GetType("Mono.Runtime") != null;
        }

        public static bool TryOpenWebsite(string url) {
            if (string.IsNullOrEmpty(url))
                return false;
            else if (System.Uri.TryCreate(url, UriKind.Absolute, out _)) {
                return TryStartProcess(url, out _);
            }
            else
                return false;
        }

        public static bool TryStartProcess(string path, out System.Diagnostics.Process process) {
            process = ProcessStart(path);
            if (process != null && process.HasExited) {
                using (process) {
                    return process.ExitCode >= 0;
                }
            }
            else
                return process != null;
        }

        //https://github.com/mono/mono/issues/17204
        //https://github.com/dotnet/runtime/issues/28005
        //https://github.com/dotnet/runtime/issues/23877
        //https://github.com/KSP-CKAN/CKAN/blob/16994590ee0318d6bb93c90455e1dead093a02cc/Core/Utilities.cs (ProcessStartURL)
        public static System.Diagnostics.Process ProcessStart(string path) {
            

            if (IsRunningOnMono()) {
                if (path.Contains(' ') && path[0] != '\'' && path[0]!='\"') {
                    //path = "'" + path + "'";//single quotes don't work in Windows ;(
                    path = "\"" + path + "\"";
                }


                foreach (string app in new[] { "xdg-open", "gnome-open", "kfmclient", "open", "explorer.exe" }) {
                    System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo(app, path);
                    psi.ErrorDialog = false;
                    //psi.UseShellExecute = true/false?;
                    try {
                        Logger.Log("Attempting to open " + path + " with " + app, Logger.EventLogEntryType.Information);
                        return System.Diagnostics.Process.Start(psi);
                    }
                    catch (System.ComponentModel.Win32Exception) {
                        continue;
                    }
                }
            }
            else {
                if (System.IO.File.Exists(path))
                    return System.Diagnostics.Process.Start(path);
                else if (System.IO.Directory.Exists(path)) {
                    if (path.Contains(' ') && path[0] != '\"')
                        path = "\"" + path + "\"";

                    return System.Diagnostics.Process.Start("explorer.exe", path);
                }
                else
                    return System.Diagnostics.Process.Start(path);
            }

            return null;
            
            
        }
    }                         
}
