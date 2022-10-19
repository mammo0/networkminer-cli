//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System.Collections.Generic;

namespace PacketParser.FileTransfer {
    public interface IFileCarver {
        IEnumerable<(string extension, long startPosition, long length)> GetCarvedFileIndices(string inputFilePath);
    }
}