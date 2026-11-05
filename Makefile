VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build linux windows test clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cypher ./cmd/cypher

linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cypher-linux-amd64 ./cmd/cypher

windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/cypher-windows-amd64.exe ./cmd/cypher

test:
	go test -race ./...

clean:
	rm -rf bin

# --- desktop client (Windows) ----------------------------------------------
WINTUN_URL := https://www.wintun.net/builds/wintun-0.14.1.zip
WINTUN_SHA256 := e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
WINTUN_DLL := cmd/nevio/assets/wintun.dll

.PHONY: gui gui-icon

# Downloads wintun.dll (amd64) and checks its hash before embedding it.
$(WINTUN_DLL):
	curl -sSfL -o wintun.zip $(WINTUN_URL)
	python3 -c "import zipfile,sys; sys.stdout.buffer.write(zipfile.ZipFile('wintun.zip').read('wintun/bin/amd64/wintun.dll'))" > $@
	rm -f wintun.zip
	echo "$(WINTUN_SHA256)  $@" | sha256sum -c - || (rm -f $@; exit 1)

# Optional: exe icon and manifest (needs network access to fetch go-winres).
gui-icon:
	cd cmd/nevio && go run github.com/tc-hib/go-winres@v0.3.3 simply \
		--icon assets/app.ico --manifest gui --arch amd64 \
		--product-name nevio --file-description "nevio VPN client" --original-filename nevio.exe

gui: $(WINTUN_DLL)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -tags wintun \
		-ldflags "$(LDFLAGS) -H windowsgui" -o bin/nevio.exe ./cmd/nevio

# --- Android client ------------------------------------------------------------
# Needs the Android SDK and NDK (ANDROID_HOME, ANDROID_NDK_HOME) and gomobile:
#   go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
ANDROID_APP_ID ?= net.nevio.app
ANDROID_APP_NAME ?= nevio
ANDROID_AAR := android/app/libs/nevio.aar

.PHONY: android android-aar

android-aar:
	mkdir -p android/app/libs
	gomobile bind -target=android/arm64,android/arm,android/amd64 -androidapi 26 \
		-javapkg net.nevio.core -trimpath -ldflags "-s -w" -o $(ANDROID_AAR) ./mobile

# bin/nevio-android.apk; ANDROID_APP_ID / ANDROID_APP_NAME change the package
# name and the visible name (see docs/android.md, «Скрытность»).
android: android-aar
	mkdir -p bin
	cd android && ./gradlew --no-daemon assembleRelease -PappVersion=$(VERSION:v%=%) \
		-PappId=$(ANDROID_APP_ID) -PappName="$(ANDROID_APP_NAME)"
	cp android/app/build/outputs/apk/release/app-release.apk bin/nevio-android.apk
