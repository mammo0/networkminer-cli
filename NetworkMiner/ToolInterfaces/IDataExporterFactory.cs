using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IDataExporterFactory {

        EventHandler ResetEventHandler { get; }

        void RegisterHandlers(PacketParser.PacketHandler packetHandler);

        IDataExporter CreateDataExporter(string filename, bool useRelativePathIfAvailable, bool preserveNewlineCharacters);
    }
}
