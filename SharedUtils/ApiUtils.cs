using System;
using System.Collections.Generic;
using System.Net;
using System.Web;


namespace SharedUtils
{
    public class ApiUtils {


        /// <summary>
        /// Throws System.Net.WebException if run under Mono without TLS 1.2 support
        /// </summary>
        /// <param name="productCode"></param>
        /// <param name="releasePost"></param>
        /// <param name="downloadUrl"></param>
        /// <returns></returns>
        public static Version GetLatestVersion(string productCode, out string releasePost, out string downloadUrl) {
#if DEBUG
            //string requestURL = "http://localhost:57978/updatecheck.ashx?l=" + System.Web.HttpUtility.UrlEncode(productCode);
            string requestURL = "https://www.netresec.com/updatecheck.ashx?l=" + System.Web.HttpUtility.UrlEncode(productCode);
#else
            string requestURL = "https://www.netresec.com/updatecheck.ashx?l=" + System.Web.HttpUtility.UrlEncode(productCode);
#endif
            if (SystemHelper.IsRunningOnMono()) {
                //https://stackoverflow.com/questions/47559814/how-do-i-persuade-mono-to-use-tls-1-2-or-later
                //Environment.SetEnvironmentVariable("MONO_TLS_PROVIDER", "btls");
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls11;
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
                //NativeMessageHandler
                //Xamarin.Android.Net.AndroidClientHandler
            }
            else
                ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;

            Logger.Log("ServicePointManager.SecurityProtocol = " + ServicePointManager.SecurityProtocol.ToString(), Logger.EventLogEntryType.Information);
            System.Net.HttpWebRequest request = System.Net.WebRequest.Create(requestURL) as System.Net.HttpWebRequest;

            string versionString = null;

            using (System.Net.WebResponse response = request.GetResponse()) {
                using (System.IO.Stream stream = response.GetResponseStream()) {
                    using (System.IO.TextReader reader = new System.IO.StreamReader(stream)) {

                        versionString = reader.ReadLine();
                        releasePost = reader.ReadLine();
                        downloadUrl = reader.ReadLine();
                    }
                }
            }
            return Version.Parse(versionString);
        }
    }
}
