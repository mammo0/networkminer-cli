using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {

    //ms-help://MS.VSCC.v80/MS.MSDN.v80/MS.NETDEVFX.v20.en/cpref2/html/T_System_EventArgs.htm
    public class AnomalyEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {
        public string Message;
        public DateTime Timestamp;

        private AnomalyEventArgs() { throw new NotImplementedException(); } //for serialization purposes

        public AnomalyEventArgs(string anomalyMessage, DateTime anomalyTimestamp) {
            this.Message=anomalyMessage;
            this.Timestamp = anomalyTimestamp;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            writer.WriteElementString("Message", this.Message);
            writer.WriteElementString("Timestamp", this.Timestamp.ToString());
        }
    }

}
