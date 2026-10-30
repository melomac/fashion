import CryptoKit
@testable import fashion
import MachO
import XCTest

final class SymHashTests: XCTestCase {
    /**
     The external symbols joined by the separator, sorted in byte order unless told otherwise, where the table's
     own order is the linker's: `_b` before `_a` here, which only the unsorted digest tells.
     */
    func testSymbolsAreJoinedSortedOrAsTheTableHasThem() throws {
        var data = self.makeMachO(symoff: 64, nsyms: 2, stroff: 56, strsize: 8)
        data.append(Data("\0_b\0_a\0\0".utf8))
        for strx in [UInt32(1), 4] {
            data.appendUInt32(strx); data.append(contentsOf: [0x01, 0, 0, 0]); data.appendUInt64(0) // n_type N_EXT
        }
        let md5 = { (joined: String) in Insecure.MD5.hash(data: Data(joined.utf8)).map { String(format: "%02x", $0) }.joined() }
        XCTAssertEqual(try SymHash.compute(File(data: data), algorithm: .md5, separator: ",", sortSymbols: true).map(\.digest), [md5("_a,_b")])
        XCTAssertEqual(try SymHash.compute(File(data: data), algorithm: .md5, separator: ",", sortSymbols: false).map(\.digest), [md5("_b,_a")])
        XCTAssertEqual(try SymHash.compute(File(data: data), algorithm: .md5, separator: "\n", sortSymbols: true).map(\.digest), [md5("_a\n_b")])
    }

    func testMalformedSymbolTableThrows() throws {
        let data = self.makeMachO(symoff: 4096, nsyms: 1, stroff: 56, strsize: 0)

        XCTAssertThrowsError(try SymHash.compute(File(data: data), algorithm: .md5, separator: "", sortSymbols: false)) { error in
            XCTAssertEqual(error as? ParserError, .invalidSymbolTableRange(offset: 4096, count: 1, fileSize: 56))
        }
    }

    func testMalformedStringTableThrows() throws {
        let data = self.makeMachO(symoff: 56, nsyms: 0, stroff: 4096, strsize: 1)

        XCTAssertThrowsError(try SymHash.compute(File(data: data), algorithm: .md5, separator: "", sortSymbols: false)) { error in
            XCTAssertEqual(error as? ParserError, .invalidStringTableRange(offset: 4096, size: 1, fileSize: 56))
        }
    }

    private func makeMachO(symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32) -> Data {
        var data = Data()
        data.appendUInt32(MH_MAGIC_64)
        data.appendInt32(CPU_TYPE_ARM64)
        data.appendInt32(0)
        data.appendUInt32(UInt32(MH_EXECUTE))
        data.appendUInt32(1)
        data.appendUInt32(UInt32(MemoryLayout<symtab_command>.size))
        data.appendUInt32(0)
        data.appendUInt32(0)
        data.appendUInt32(UInt32(LC_SYMTAB))
        data.appendUInt32(UInt32(MemoryLayout<symtab_command>.size))
        data.appendUInt32(symoff)
        data.appendUInt32(nsyms)
        data.appendUInt32(stroff)
        data.appendUInt32(strsize)
        return data
    }
}
