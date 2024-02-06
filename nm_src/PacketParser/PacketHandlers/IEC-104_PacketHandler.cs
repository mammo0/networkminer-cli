using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PacketParser.Packets;

namespace PacketParser.PacketHandlers {
    class IEC_104_PacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        //https://infosys.beckhoff.com/english.php?content=../content/1033/tf6500_tc3_iec60870_5_10x/984447883.html&id=4468958939044453278
        //https://infosys.beckhoff.com/english.php?content=../content/1033/tf6500_tc3_iec60870_5_10x/984447883.html&id=4468958939044453278


        /**
         * ASDU IOA + Values => Parameters tab
         * Parameter name = IOA (IEC-101 7.2.5 INFORMATION OBJECT ADDRESS)
         * Parameter value = Value + Status
         * 
         * Status is important because status can change
         * while value remains the same.
         * 
         * Somewhere needs to go Cause of
         * transmission(CauseTx in wireshark), TypeID and Common Address of
         * ASDU(Addr in Wireshark). TypeID and CauseTx to Details field, for
         * instance "M_SP_TB_1(Single-point), interrogation". I think Common
         * address of ASDU is suited more to Hosts tab under Host Details.
         * 
         **/

        private readonly PopularityList<string, PacketParser.FileTransfer.FileSegmentAssembler> fileSegmentAssemblerList;
        private readonly PopularityList<(NetworkTcpSession tcpSession, ushort fileID), uint> fileSizeList;
        private readonly PopularityList<(NetworkTcpSession tcpSession, ushort fileID, byte section), FileTransfer.ContentRange> sectionContentRangeList;

        /**
         * We need a mapping like this:
         * AsduTypeID => InformationElement with ValueParser
         * */

        public override Type[] ParsedTypes { get; } = { typeof(Packets.IEC_60870_5_104Packet) };

        public IEC_104_PacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.fileSegmentAssemblerList = new PopularityList<string, FileTransfer.FileSegmentAssembler>(100);
            this.fileSegmentAssemblerList.PopularityLost += (k, assembler) => assembler.Close();
            this.fileSizeList = new PopularityList<(NetworkTcpSession tcpSession, ushort fileID), uint>(100);
            this.sectionContentRangeList = new PopularityList<(NetworkTcpSession tcpSession, ushort fileID, byte section), FileTransfer.ContentRange>(100);
        }


        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.IEC_104; }
        }

        


        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<AbstractPacket> packetList) {
            int returnValue = 0;
            foreach (Packets.AbstractPacket p in packetList) {
                if (p.GetType() == typeof(Packets.IEC_60870_5_104Packet))
                    returnValue = ExtractData(tcpSession, transferIsClientToServer, (Packets.IEC_60870_5_104Packet)p);
            }

            return returnValue;
        }

        private int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, Packets.IEC_60870_5_104Packet iec104Packet) {
        
        
            //TODO extract data
            if (iec104Packet.AsduData != null && iec104Packet.AsduData.Length > 0) {
                //int addressLength = 3; //Can be 1, 2 or 3 !?
                int ioaOffset = 3;//typeID, noObjects, vauseTX
                if (iec104Packet.Settings.causeOfTransmissionHasOriginatorAddress)
                    ioaOffset++;
                ioaOffset += iec104Packet.Settings.asduAddressLength;

                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                string details = "IEC 60870-5-104 ASDU Type ID " + iec104Packet.AsduTypeID.ToString()
                    + ", CauseTX " + ((byte) iec104Packet.CauseOfTransmission)
                    + " (" + iec104Packet.CauseOfTransmission.ToString()  + ")";
                if (iec104Packet.CauseOfTransmissionNegativeConfirm)
                    details += " NEGATIVE";
                if (iec104Packet.CauseOfTransmissionTest)
                    details += " TEST";


                try {
                    uint asduIOA = 0;
                    bool sequenceOfElements = false;
                    
                    int lastItemStartPosition = iec104Packet.AsduData.Length - iec104Packet.Settings.ioaLength;
                    if (iec104Packet.AsduInformationObjectCount > 1 && iec104Packet.AsduInformationObjectCountIsElementCount) {
                        sequenceOfElements = true;
                        lastItemStartPosition = iec104Packet.AsduData.Length - 1;
                        if(!(new byte[] { 1, 3, 5, 7, 9, 11, 13, 15, 20, 21, 126 }).Any(b => iec104Packet.AsduTypeID.Value == b)) {
                            base.MainPacketHandler.OnAnomalyDetected("Element sequence defined in IEC 60870-5-104 Type ID " + iec104Packet.AsduTypeID.Value + " packet, which only support object sequences. Frame " + iec104Packet.ParentFrame.FrameNumber, iec104Packet.ParentFrame.Timestamp);
                        }
                    }
                    while (parameters.Count < iec104Packet.AsduInformationObjectCount && ioaOffset < lastItemStartPosition) {
                        if (parameters.Count == 0 || !sequenceOfElements) {
                            asduIOA = Utils.ByteConverter.ToUInt32(iec104Packet.AsduData, ioaOffset, iec104Packet.Settings.ioaLength, true);
                            ioaOffset += iec104Packet.Settings.ioaLength;
                        }
                        else
                            asduIOA++;
                        //COA = Common Address of ASDU (also referred to as "Station Address")
                        string addressString = "COA " + iec104Packet.AsduAddress.ToString() + " IOA " + asduIOA.ToString();


                        if (iec104Packet.AsduTypeID.Value == 1) {
                            //M_SP_NA_1 - 1 - Single-point information
                            Packets.IEC_60870_5_104Packet.SIQ siq = new Packets.IEC_60870_5_104Packet.SIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += siq.Length;
                            parameters.Add(addressString, siq.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 3) {
                            //M_DP_NA_1 - Double-point information without time tag
                            //7.2.6.2 Double-point information (IEV 371-02-08) with quality descriptor
                            Packets.IEC_60870_5_104Packet.DIQ diq = new Packets.IEC_60870_5_104Packet.DIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += diq.Length;
                            parameters.Add(addressString, diq.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 5) {
                            //7.3.1.5 TYPE IDENT 5: M_ST_NA_1
                            //Step position information
                            IEC_60870_5_104Packet.VTI vti = new IEC_60870_5_104Packet.VTI(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += vti.Length;
                            IEC_60870_5_104Packet.QDS qds = new IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset -= qds.Length;
                            parameters.Add(addressString, vti.ToString() + " (" + qds.ToString() + ")");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 7) {
                            //7.3.1.7 TYPE IDENT 7: M_BO_NA_1
                            //Bitstring of 32 bit
                            IEC_60870_5_104Packet.BSI bsi = new IEC_60870_5_104Packet.BSI(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += bsi.Length;
                            IEC_60870_5_104Packet.QDS qds = new IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset -= qds.Length;
                            parameters.Add(addressString, bsi.ToString() + " (" + qds.ToString() + ")");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 9) {
                            //7.3.1.9 TYPE IDENT 9: M_ME_NA_1 - Measured value, normalized value

                            //NVA = Normalized value, defined in 7.2.6.6
                            Packets.IEC_60870_5_104Packet.NVA nva = new Packets.IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            //QDS 7.2.6.3
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            parameters.Add(addressString, nva.ToString() + " (" + qds.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 11) {
                            //IEC 101 - 7.3.1.11 TYPE IDENT 11: M_ME_NB_1 Measured value, scaled value

                            //SVA = 7.2.6.7 Scaled value
                            Packets.IEC_60870_5_104Packet.SVA sva = new Packets.IEC_60870_5_104Packet.SVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sva.Length;
                            //QDS 7.2.6.3
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            parameters.Add(addressString, sva.ToString() + " (" + qds.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 13) {
                            //IEC 101 - 7.3.1.13 TYPE IDENT 13: M_ME_NC_1 Measured value, short floating point number

                            //IEEE STD 754 32 bit float
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            parameters.Add(addressString, binary32Float.ToString() + " (" + qds.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 30) {
                            //M_SP_TB_1 - Single-point information with time tag CP56Time2a
                            Packets.IEC_60870_5_104Packet.SIQ siq = new Packets.IEC_60870_5_104Packet.SIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += siq.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, siq.ToString() + " " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 31) {
                            //7.3.1.23 TYPE IDENT 31
                            //M_DP_TB_1 Double-point information with time tag CP56Time2a

                            //DIQ = Double-point information with quality descriptor, defined in 7.2.6.2
                            Packets.IEC_60870_5_104Packet.DIQ diq = new Packets.IEC_60870_5_104Packet.DIQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += diq.Length;

                            //Seven octet binary time
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, diq.ToString() + " " + time.ToString());

                        }
                        else if (iec104Packet.AsduTypeID.Value == 32) {
                            //7.3.1.24 TYPE IDENT 32: M_ST_TB_1
                            //Step position information with time tag CP56Time2a

                            //VTI = Value with transient state indication, defined in 7.2.6.5
                            IEC_60870_5_104Packet.VTI vti = new IEC_60870_5_104Packet.VTI(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += vti.Length;

                            //QDS = Quality descriptor
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;

                            //Seven octet binary time
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, vti.ToString() + " (" + qds.ToString() + ") " + time.ToString());

                        }
                        else if (iec104Packet.AsduTypeID.Value == 33) {
                            //7.3.1.25 TYPE IDENT 33: M_BO_TB_1
                            //Bitstring of 32 bits with time tag CP56Time2a

                            //nva
                            Packets.IEC_60870_5_104Packet.BSI bsi = new Packets.IEC_60870_5_104Packet.BSI(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += bsi.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            //7 octet time (CP56Time2a)
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, bsi.ToString() + " (" + qds.ToString() + ") " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 34) {
                            //7.3.1.26 TYPE IDENT 34: M_ME_TD_1 - Measured value, normalized value with time tag CP56Time2a

                            //nva
                            Packets.IEC_60870_5_104Packet.NVA nva = new Packets.IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            //7 octet time (CP56Time2a)
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, nva.ToString() + " (" + qds.ToString() + ") " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 35) {
                            //7.3.1.27 TYPE IDENT 35: M_ME_TE_1
                            //Measured value, scaled value with time tag CP56Time2a

                            //sva
                            Packets.IEC_60870_5_104Packet.SVA sva = new Packets.IEC_60870_5_104Packet.SVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sva.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            //7 octet time (CP56Time2a)
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, sva.ToString() + " (" + qds.ToString() + ") " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 36) {
                            //IEC 101 - 7.3.1.28 TYPE IDENT 36: M_ME_TF_1 Measured value, short floating point number with time tag CP56Time2a
                            //IEC 104 <36> := measured value, short floating point number with time tag CP56Time2a M_ME_TF_1

                            //IEEE STD 754 32 bit float
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            //qds
                            Packets.IEC_60870_5_104Packet.QDS qds = new Packets.IEC_60870_5_104Packet.QDS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qds.Length;
                            //7 octet time (CP56Time2a)
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, binary32Float.ToString() + " (" + qds.ToString() + ") " + time.ToString());

                        }
                        else if (iec104Packet.AsduTypeID.Value == 45) {
                            //7.3.2.1 TYPE IDENT 45: C_SC_NA_1 - Single command

                            //SCO = QU Single command, defined in 7.2.6.15
                            Packets.IEC_60870_5_104Packet.SCO sco = new Packets.IEC_60870_5_104Packet.SCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sco.Length;
                            parameters.Add(addressString, sco.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 46) {
                            //7.3.2.2 TYPE IDENT 46: C_DC_NA_1 - Double command

                            //DCO = Double command, defined in 7.2.6.16
                            Packets.IEC_60870_5_104Packet.DCO dco = new Packets.IEC_60870_5_104Packet.DCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += dco.Length;
                            parameters.Add(addressString, dco.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 47) {
                            //TYPE IDENT 47: C_RC_NA_1
                            //Regulating step command
                            IEC_60870_5_104Packet.RCO rco = new IEC_60870_5_104Packet.RCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += rco.Length;
                            parameters.Add(addressString, rco.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 48) {
                            //TYPE IDENT 48: C_SE_NA_1
                            //Set-point command, normalized value
                            IEC_60870_5_104Packet.NVA nva = new IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            parameters.Add(addressString, nva.ToString() + " (" + qos.ToString() + ")");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 49) {
                            //7.3.2.5 TYPE IDENT 49: C_SE_NB_1
                            //Set-point command, scaled value
                            IEC_60870_5_104Packet.SVA sva = new IEC_60870_5_104Packet.SVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sva.Length;
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            parameters.Add(addressString, sva.ToString() + " (" + qos.ToString() + ")");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 50) {
                            //IEC 101 - 7.3.2.6 TYPE IDENT 50: C_SE_NC_1 Set-point command, short floating point number (similar to type ID 13)

                            //IEEE STD 754 32 bit float
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            //qos = quality of set-point command
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            parameters.Add(addressString, binary32Float.ToString() + " (" + qos.ToString() + ")");

                        }
                        else if (iec104Packet.AsduTypeID.Value == 51) {
                            //7.3.2.7 TYPE IDENT 51: C_BO_NA_1
                            //Bitstring of 32 bit

                            //bsi
                            Packets.IEC_60870_5_104Packet.BSI bsi = new Packets.IEC_60870_5_104Packet.BSI(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += bsi.Length;
                            parameters.Add(addressString, bsi.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 58) {
                            //IEC 104 - 8.1 TYPE IDENT 58: C_SC_TA_1 Single command with time tag CP56Time2a
                            Packets.IEC_60870_5_104Packet.SCO sco = new Packets.IEC_60870_5_104Packet.SCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sco.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, sco.ToString() + " " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 59) {
                            //IEC 104 - 8.2 TYPE IDENT 59: C_DC_TA_1 Double command with time tag CP56Time2a
                            Packets.IEC_60870_5_104Packet.DCO dco = new Packets.IEC_60870_5_104Packet.DCO(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += dco.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, dco.ToString() + " " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 61) {
                            //IEC 104 - 8.4 TYPE IDENT 61: C_SE_TA_1 Set-point command with time tag CP56Time2a, normalized value 
                            Packets.IEC_60870_5_104Packet.NVA nva = new Packets.IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, nva.ToString() + " (" + qos.ToString() + ") " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 63) {
                            //IEC 104 - 8.6 TYPE IDENT 63: C_SE_TC_1 Set-point command with time tag CP56Time2a, short floating point number
                            Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754 binary32Float = new Packets.IEC_60870_5_104Packet.R32_IEEE_STD_754(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += binary32Float.Length;
                            Packets.IEC_60870_5_104Packet.QOS qos = new Packets.IEC_60870_5_104Packet.QOS(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qos.Length;
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            parameters.Add(addressString, binary32Float.ToString() + " (" + qos.ToString() + ") " + time.ToString());
                        }
                        //TODO: 70 (JavaRMI_and...)
                        else if (iec104Packet.AsduTypeID.Value == 70) {
                            //7.3.3.1 TYPE IDENT 70: M_EI_NA_1
                            //End of initialization
                            ioaOffset += 1;
                            parameters.Add(addressString, "End of Initialization");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 100) {
                            //7.3.4.1 TYPE IDENT 100: C_IC_NA_1


                            //QOI = Qualifier of UI8 interrogation, defined in 7.2.6.22
                            Packets.IEC_60870_5_104Packet.QOI qoi = new Packets.IEC_60870_5_104Packet.QOI(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qoi.Length;
                            parameters.Add(addressString, qoi.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 101) {
                            //7.3.4.2 TYPE IDENT 101: C_CI_NA_1
                            //Counter interrogation command


                            //QCC = Qualifier of counter interrogation command, defined in 7.2.6.23
                            Packets.IEC_60870_5_104Packet.QCC qcc = new Packets.IEC_60870_5_104Packet.QCC(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qcc.Length;
                            parameters.Add(addressString, qcc.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 103) {
                            //TYPE IDENT 103: C_CS_NA_1
                            //Clock synchronization command

                            //Seven octet binary time
                            Packets.IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;
                            //TODO
                            parameters.Add(addressString, "Clock Synchronization: " + time.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 105) {
                            //7.3.4.6 TYPE IDENT 105: C_RP_NA_1
                            //Reset process command
                            byte qrp = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            if (qrp == 1)
                                parameters.Add(addressString, "General Reset of Process");
                            else if(qrp == 2)
                                parameters.Add(addressString, "Reset of Pending Information with Time Tag of the Event Buffer");
                            else
                                parameters.Add(addressString, "Reset (" + qrp.ToString() + ")");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 110) {
                            //7.3.5.1 TYPE IDENT 110: P_ME_NA_1
                            //Parameter of measured values, normalized value

                            //NVA
                            IEC_60870_5_104Packet.NVA nva = new IEC_60870_5_104Packet.NVA(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nva.Length;
                            //QPM
                            IEC_60870_5_104Packet.QPM qpm = new IEC_60870_5_104Packet.QPM(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += qpm.Length;

                            parameters.Add(addressString, nva.ToString() + " (" +qpm.ToString()+ ")");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 120) {
                            //7.3.6.1 TYPE IDENT 120: F_FR_NA_1
                            //File ready

                            /**
                             * File transfers are used to transmit disturbance data generated by relay protection equipment
                             * Protection equipment establishes a list of recorded disturbances (directory).
                             * This list of recorded disturbances is mapped in a subdirectory F_DR_TA_1.
                             * The transmission to the controlling station is performed separately for each file.
                            **/



                            //name of file
                            IEC_60870_5_104Packet.NOF nof = new IEC_60870_5_104Packet.NOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nof.Length;
                            //length of file
                            IEC_60870_5_104Packet.LOF lof = new IEC_60870_5_104Packet.LOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += lof.Length;
                            //file ready
                            IEC_60870_5_104Packet.FRQ frq = new IEC_60870_5_104Packet.FRQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += frq.Length;
                            parameters.Add(addressString, "File " + nof.FileID + " " + frq.ToString() + " (" + lof.FileOrSectionLength + " bytes)");
                            this.fileSizeList[(tcpSession, nof.FileID)] = lof.FileOrSectionLength;
                        }
                        else if (iec104Packet.AsduTypeID.Value == 121) {
                            //7.3.6.2 TYPE IDENT 121: F_SR_NA_1
                            //Section ready

                            //name of file
                            IEC_60870_5_104Packet.NOF nof = new IEC_60870_5_104Packet.NOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nof.Length;
                            //name of section
                            byte sectionID = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            //length of section
                            IEC_60870_5_104Packet.LOF los = new IEC_60870_5_104Packet.LOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += los.Length;
                            //skip section ready
                            string sectionReadyString;
                            if ((iec104Packet.AsduData[ioaOffset] & 0xf0) == 0)
                                sectionReadyString = "Ready";
                            else
                                sectionReadyString = "Not Ready";
                            ioaOffset++;
                            parameters.Add(addressString, "File " + nof.FileID + " Section " + sectionID + " " + sectionReadyString + " (" + los.FileOrSectionLength + " bytes)");
                            //FiveTuple fiveTuple = new FiveTuple(tcpSession.ClientHost, tcpSession.ClientTcpPort, tcpSession.ServerHost, tcpSession.ServerTcpPort, FiveTuple.TransportProtocol.TCP);
                            //string assemblerKey = this.GetAssemblerKey(fiveTuple, nof.FileID, sectionID);
                            string assemblerKey = this.GetAssemblerKey(tcpSession, iec104Packet, asduIOA, nof.FileID, sectionID);
                            string path = "";
                            string fileName = assemblerKey;

                            if (this.fileSegmentAssemblerList.ContainsKey(assemblerKey)) {
                                var oldAssembler = this.fileSegmentAssemblerList[assemblerKey];
                                oldAssembler.Close();
                            }

                            FileTransfer.FileSegmentAssembler assembler = new FileTransfer.FileSegmentAssembler(path, tcpSession, transferIsClientToServer, fileName, assemblerKey, this.MainPacketHandler.FileStreamAssemblerList, this.fileSegmentAssemblerList, FileTransfer.FileStreamTypes.IEC104, "", tcpSession.ServerHost.HostName);
                            assembler.SegmentSize = los.FileOrSectionLength;
                            this.fileSegmentAssemblerList.Add(assemblerKey, assembler);

                            if (this.fileSizeList.ContainsKey((tcpSession, nof.FileID))) {
                                FileTransfer.ContentRange contentRange = null;
                                if (sectionID == 1) {
                                    contentRange = new FileTransfer.ContentRange() {
                                        Start = 0,
                                        End = los.FileOrSectionLength - 1,
                                        Total = this.fileSizeList[(tcpSession, nof.FileID)]
                                    };
                                    this.sectionContentRangeList[(tcpSession, nof.FileID, sectionID)] = contentRange;
                                }
                                else {
                                    if (this.sectionContentRangeList.ContainsKey((tcpSession, nof.FileID, (byte)(sectionID - 1)))) {
                                        FileTransfer.ContentRange previousRange = this.sectionContentRangeList[(tcpSession, nof.FileID, (byte)(sectionID - 1))];
                                        contentRange = new FileTransfer.ContentRange() {
                                            Start = previousRange.End + 1,
                                            End = previousRange.End + los.FileOrSectionLength,
                                            Total = previousRange.Total
                                        };
                                        this.sectionContentRangeList[(tcpSession, nof.FileID, sectionID)] = contentRange;
                                    }
                                }
                                if (contentRange != null)
                                    assembler.TotalFileNameAndRange = (iec104Packet.AsduAddress + "_" + asduIOA + "_" + nof.FileID.ToString(), contentRange);
                            }
                        }
                        else if (iec104Packet.AsduTypeID.Value == 122) {
                            //7.3.6.3 TYPE IDENT 122: F_SC_NA_1
                            //Call directory, select file, call file, call section

                            //name of file
                            IEC_60870_5_104Packet.NOF nof = new IEC_60870_5_104Packet.NOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nof.Length;
                            //name of section
                            ioaOffset++;
                            //SCQ = Select and call qualifier
                            IEC_60870_5_104Packet.SCQ scq = new IEC_60870_5_104Packet.SCQ(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += scq.Length;
                            parameters.Add(addressString, "File " + nof.FileID + " " + scq.ToString());
                        }
                        else if (iec104Packet.AsduTypeID.Value == 123) {
                            //7.3.6.4 TYPE IDENT 123: F_LS_NA_1
                            //Last section, last segment
                            IEC_60870_5_104Packet.NOF nof = new IEC_60870_5_104Packet.NOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nof.Length;
                            //name of section
                            byte sectionID = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            //length of segment
                            byte lsq = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            parameters.Add(addressString, "File " + nof.FileID + " Section " + sectionID + " Completed");
                        }
                        else if (iec104Packet.AsduTypeID.Value == 124) {
                            //7.3.6.5 TYPE IDENT 124: F_AF_NA_1
                            //ACK file, ACK section
                            IEC_60870_5_104Packet.NOF nof = new IEC_60870_5_104Packet.NOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nof.Length;
                            //name of section
                            byte sectionID = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            byte ack = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            if (ack == 0x03)
                                parameters.Add(addressString, "File " + nof.FileID + " Section " + sectionID + " ACK Section");
                            else if (ack == 0x01)
                                parameters.Add(addressString, "File " + nof.FileID + " Section " + sectionID + " ACK File");
                            else {
                                parameters.Add(addressString, "File " + nof.FileID + " Section " + sectionID + " Error (0x" + ack.ToString("x2") + ")");
                                //remove section data with error
                                string assemblerKey = this.GetAssemblerKey(tcpSession, iec104Packet, asduIOA, nof.FileID, sectionID);
                                if (this.fileSegmentAssemblerList.ContainsKey(assemblerKey)) {
                                    this.fileSegmentAssemblerList[assemblerKey].Close();
                                }

                            }
                        }
                        else if (iec104Packet.AsduTypeID.Value == 125) {
                            //7.3.6.6 TYPE IDENT 125: F_SG_NA_1
                            //Segment

                            IEC_60870_5_104Packet.NOF nof = new IEC_60870_5_104Packet.NOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nof.Length;
                            //name of section
                            byte sectionID = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            //length of segment
                            byte lengthOfSegment = iec104Packet.AsduData[ioaOffset];
                            ioaOffset++;
                            byte[] segmentData = new byte[lengthOfSegment];
                            Array.Copy(iec104Packet.AsduData, ioaOffset, segmentData, 0, segmentData.Length);
                            parameters.Add(addressString, "File " + nof.FileID + " Section " + sectionID + " Data (" + lengthOfSegment + " bytes)");

                            //FiveTuple fiveTuple = new FiveTuple(tcpSession.ClientHost, tcpSession.ClientTcpPort, tcpSession.ServerHost, tcpSession.ServerTcpPort, FiveTuple.TransportProtocol.TCP);
                            string assemblerKey = this.GetAssemblerKey(tcpSession, iec104Packet, asduIOA, nof.FileID, sectionID);
                            if (this.fileSegmentAssemblerList.ContainsKey(assemblerKey)) {
                                var assembler = this.fileSegmentAssemblerList[assemblerKey];
                                assembler.AddData(segmentData, iec104Packet.ParentFrame);
                            }

                        }
                        else if(iec104Packet.AsduTypeID.Value == 126) {
                            //7.3.6.7 TYPE IDENT 126: F_DR_TA_1
                            //Defined in 7.2.6.33 Name of file or subdirectory
                            IEC_60870_5_104Packet.NOF nof = new IEC_60870_5_104Packet.NOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += nof.Length;//2 bytes
                            //Defined in 7.2.6.35 Length of file
                            IEC_60870_5_104Packet.LOF lof = new IEC_60870_5_104Packet.LOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += lof.Length;//3 bytes
                            //Defined in 7.2.6.38 SOF = Status of file, defined in 7.2.6.38
                            IEC_60870_5_104Packet.SOF sof = new IEC_60870_5_104Packet.SOF(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += sof.Length;
                            //CP56Time2a
                            IEC_60870_5_104Packet.CP56Time2a time = new Packets.IEC_60870_5_104Packet.CP56Time2a(iec104Packet.AsduData, ioaOffset);
                            ioaOffset += time.Length;// 7 bytes
                            if (sof.IsDirectory)
                                parameters.Add(addressString, "Directory " + nof.FileID + ", " + lof.FileOrSectionLength + " B, " + time.ToString());
                            else
                                parameters.Add(addressString, "File " + nof.FileID + ", " + lof.FileOrSectionLength + " B, " + time.ToString());
                        }
                        else {
                            //IOA value is NOT always 1 byte!
                            //let's make a qualified guess about the IOA value length!


                            int bytesPerAsduInformationObject = (iec104Packet.AsduData.Length - ioaOffset + iec104Packet.Settings.ioaLength) / (iec104Packet.AsduInformationObjectCount - parameters.Count);
                            int bytesPerValue = bytesPerAsduInformationObject - iec104Packet.Settings.ioaLength;


                            //TODO verify that the value is reasonable
                            if (bytesPerValue > 0) {
                                string ioaValueString = Utils.ByteConverter.ToHexString(iec104Packet.AsduData, bytesPerValue, ioaOffset);
                                //uint ioaValue = Utils.ByteConverter.ToUInt32(iec104Packet.AsduData, ioaOffset, bytesPerValue);
                                //byte ioaValue = iec104Packet.AsduData[ioaOffset];
                                ioaOffset += bytesPerValue;
                                parameters.Add(addressString, ioaValueString);
                            }
                            else if (bytesPerValue == 0) {
                                parameters.Add(addressString, "");
                            }
                            else {
                                //System.Diagnostics.Debugger.Break();
                                //parameters.Add(ioaString, "");
                                //base.MainPacketHandler.OnAnomalyDetected("Incorrect IEC 60870-5-104 ASDU Information Object in Frame " + iec104Packet.ParentFrame.FrameNumber);
                                throw new Exception();
                            }
                        }
                    }
                }
                catch (Exception e) {
                    base.MainPacketHandler.OnAnomalyDetected("Incorrect IEC 60870-5-104 ASDU Information Object in Frame " + iec104Packet.ParentFrame.FrameNumber, iec104Packet.ParentFrame.Timestamp);
                }

                if (parameters.Count > 0)
                    base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(iec104Packet.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, iec104Packet.ParentFrame.Timestamp, details));
            }
            return Math.Min(iec104Packet.ApduLength + 2, iec104Packet.PacketLength);
        }

        private string GetAssemblerKey(NetworkTcpSession tcpSession, IEC_60870_5_104Packet iec104Packet, uint asduIOA, ushort file, byte section) {
            FiveTuple fiveTuple = new FiveTuple(tcpSession.ClientHost, tcpSession.ClientTcpPort, tcpSession.ServerHost, tcpSession.ServerTcpPort, FiveTuple.TransportProtocol.TCP);
            return this.GetAssemblerKey(fiveTuple, iec104Packet, asduIOA, file, section);
        }
        private string GetAssemblerKey(FiveTuple fiveTuple, IEC_60870_5_104Packet iec104Packet, uint asduIOA, ushort file, byte section) {
            //iec104Packet.AsduAddress.ToString() + " IOA " + asduIOA.ToString()
            return iec104Packet.AsduAddress + "_" + asduIOA.ToString() + "_" + file.ToString() + "_" + fiveTuple.GetHashCode().ToString("X8") + ".part" + section.ToString();
        }

        public void Reset() {
            List<FileTransfer.FileSegmentAssembler> assemblers = new List<FileTransfer.FileSegmentAssembler>(this.fileSegmentAssemblerList.GetValueEnumerator());

            foreach (var assembler in assemblers) {
                try {
                    assembler.Close();
                }
                catch (Exception e){
                    SharedUtils.Logger.Log("Unable to close file segment assembler: " + e.Message, SharedUtils.Logger.EventLogEntryType.Error);
                }
            }
            this.fileSegmentAssemblerList.Clear();
            this.fileSizeList.Clear();
            this.sectionContentRangeList.Clear();
            //TODO add resetter for identified lengths of iec104Packet.Settings (ASDU lengths and more)
        }

        
    }
}
