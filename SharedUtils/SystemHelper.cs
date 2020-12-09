using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharedUtils {
    public class SystemHelper {

        public static bool IsRunningOnMono() {
            return Type.GetType("Mono.Runtime") != null;
        }

        //https://github.com/mono/mono/issues/17204
        //https://github.com/dotnet/runtime/issues/28005
        //https://github.com/dotnet/runtime/issues/23877
        //https://github.com/KSP-CKAN/CKAN/blob/16994590ee0318d6bb93c90455e1dead093a02cc/Core/Utilities.cs (ProcessStartURL)
        public static void ProcessStart(string path) {
            

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
                        System.Diagnostics.Process.Start(psi);
                    }
                    catch (System.ComponentModel.Win32Exception) {
                        continue;
                    }
                    break;
                }
            }
            else {
                if (System.IO.File.Exists(path))
                    System.Diagnostics.Process.Start(path);
                else if (System.IO.Directory.Exists(path)) {
                    if (path.Contains(' ') && path[0] != '\"')
                        path = "\"" + path + "\"";

                    System.Diagnostics.Process.Start("explorer.exe", path);
                }
                else
                    System.Diagnostics.Process.Start(path);
            }

            
            
        }
    }                         
}
