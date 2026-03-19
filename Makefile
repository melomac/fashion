.PHONY: all
all: release

# ----------------------------------------------------------------------------
# Swift
# ----------------------------------------------------------------------------

PRODUCT_NAME = fashion
INSTALL_PATH ?= /usr/local/bin/

.PHONY: debug
debug:
	swift build

.PHONY: test
test:
	swift test --enable-code-coverage

.PHONY: format
format:
	swiftformat . --verbose

.PHONY: clean
clean:
	swift package clean

.PHONY: install
install: release
	cp /tmp/$(PRODUCT_NAME).dst/usr/local/bin/$(PRODUCT_NAME) $(INSTALL_PATH)


# ----------------------------------------------------------------------------
# Xcode
# ----------------------------------------------------------------------------

CONFIG_PATH ?= $(PRODUCT_NAME).xcconfig
XCODE_FLAGS = -scheme $(PRODUCT_NAME) -xcconfig $(CONFIG_PATH)
BUILD_FLAGS = -target $(PRODUCT_NAME) -destination generic/platform=macOS
TEST_FLAGS = -target $(PRODUCT_NAME)Tests -destination platform=macOS

.PHONY: release
release: xcode
	xcodebuild build $(XCODE_FLAGS) $(BUILD_FLAGS) -configuration Release

.PHONY: xcode-debug
xcode-debug: xcode
	xcodebuild build $(XCODE_FLAGS) $(BUILD_FLAGS) -configuration Debug

.PHONY: xcode-test
xcode-test: xcode
	xcodebuild test $(XCODE_FLAGS) $(TEST_FLAGS)

.PHONY: xcode-clean
xcode-clean: xcode
	xcodebuild clean $(XCODE_FLAGS) $(BUILD_FLAGS)
	xcodebuild clean $(XCODE_FLAGS) $(TEST_FLAGS)


# ----------------------------------------------------------------------------
# Housekeeping
# ----------------------------------------------------------------------------

.PHONY: distclean
distclean: clean xcode-clean
	git clean -dx --force --force

.PHONY: xcode
xcode:
	xcode-select --print-path
	xcodebuild -runFirstLaunch
