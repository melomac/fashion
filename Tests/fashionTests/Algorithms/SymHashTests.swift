@testable import fashion
import MachO
import XCTest

final class SymHashTests: XCTestCase {
    func testMalformedSymbolTableThrows() throws {
        let data = self.makeMachO(symoff: 4096, nsyms: 1, stroff: 56, strsize: 0)
        let url = FileManager.default.temporaryDirectory / "fashion-symhash-symbols-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertThrowsError(try SymHash.compute(path: url.path(), algorithm: .md5, separator: "", sortSymbols: false)) { error in
            XCTAssertEqual(error as? ParserError, .invalidSymbolTableRange(offset: 4096, count: 1, fileSize: 56))
        }
    }

    func testMalformedStringTableThrows() throws {
        let data = self.makeMachO(symoff: 56, nsyms: 0, stroff: 4096, strsize: 1)
        let url = FileManager.default.temporaryDirectory / "fashion-symhash-strings-\(UUID())"
        try data.write(to: url)
        defer {
            try? FileManager.default.removeItem(at: url)
        }

        XCTAssertThrowsError(try SymHash.compute(path: url.path(), algorithm: .md5, separator: "", sortSymbols: false)) { error in
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
