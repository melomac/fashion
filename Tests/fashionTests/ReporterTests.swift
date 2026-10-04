@testable import fashion
import XCTest

final class ReporterTests: XCTestCase {
    /**
     The peak reported on ⌃T and at the end of a run is the kernel's high-water mark: a spike freed before the report
     still counts, with no sampling in between.
     */
    func testPeakFootprintKeepsFreedSpike() throws {
        let before = try XCTUnwrap(Reporter.peakFootprint())
        let size = Int(before) + 16 << 20 // above any earlier peak of the test process
        guard let pages = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0), pages != MAP_FAILED else {
            return XCTFail("mmap of \(size) bytes failed")
        }

        memset(pages, 1, size) // dirty every page, so it counts toward the footprint
        munmap(pages, size)

        XCTAssertGreaterThanOrEqual(try XCTUnwrap(Reporter.peakFootprint()), Int64(size))
    }
}
