//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace NetworkWrapper {
    public class WinPCapAdapter : IAdapter{
        private string npfName;// for example "\Device\NPF_{XXXXX}"
        private string description;//for example "3Com EtherLink PCI"
        private string ipAddress;//The IP-address
        private string netmask;//For example 255.255.255.0 ???

        internal string NPFName { get { return this.npfName; } }

        internal WinPCapAdapter(Device device){
            this.ipAddress=device.Address;
            this.description=device.Description;
            this.npfName=device.Name;
            this.netmask=device.Netmask;
        }

        public override string ToString() {
            StringBuilder returnString=new StringBuilder("WinPcap: "+this.description);
            if(ipAddress!=null && ipAddress.Length>6) {
                returnString.Append(" ("+ipAddress+")");
            }
            if(npfName.Contains("{"))
                returnString.Append(" "+npfName.Substring(npfName.IndexOf('{')));
            else
                returnString.Append(" "+npfName);
            return returnString.ToString();
            //return "WinPcap: "+this.description+" "+npfName.Substring(12);
        }

        public static List<IAdapter> GetAdapters(int millisecondsTimeout = 1000) {
            if (millisecondsTimeout > 0) {
                //Let's wrap this peice of unmanaged code in a task in order to handle timeouts better
                var getAdapterTask = System.Threading.Tasks.Task.Factory.StartNew<List<IAdapter>>(() => {
                    //To use Nicolas .NET wrapper for WinPcap:
                    List<IAdapter> deviceList = new List<IAdapter>();
                    try
                    {
                        foreach (Device d in WinPCapWrapper.FindAllDevs())
                            deviceList.Add(new WinPCapAdapter((Device)d));
                    }
                    catch (System.DllNotFoundException) {
                        //"Unable to load DLL 'wpcap.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)"
                    }
#if DEBUG
                    catch(Exception e) {
                        SharedUtils.Logger.Log(e.ToString(), SharedUtils.Logger.EventLogEntryType.Error);
                        SharedUtils.Logger.Log(e.StackTrace, SharedUtils.Logger.EventLogEntryType.Error);
                    }
#endif
                    return deviceList;
                });

                //getAdapterTask.ContinueWith(t => { /* error handling */ }, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);

                //problem: the task might throw an exception
                if (getAdapterTask.Wait(millisecondsTimeout))
                {
                    return getAdapterTask.Result;
                }
                else
                    throw new TimeoutException("Timeout while getting WinPCap Adapters");

            }
            else {
                List<IAdapter> deviceList = new List<IAdapter>();
                foreach (Device d in WinPCapWrapper.FindAllDevs())
                    deviceList.Add(new WinPCapAdapter((Device)d));
                return deviceList;
            }


            //To use the old dotNetPcap dll file:
            /*
            System.Collections.ArrayList tmpList;
            tmpList=dotnetWinpCap.FindAllDevs();

            List<IAdapter> devices=new List<IAdapter>(tmpList.Count);

            foreach(object d in tmpList) {
                devices.Add(new WinPCapAdapter((Device)d));
            }
            return devices;
            */
        }
    }
}
