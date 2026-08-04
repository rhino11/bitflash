# Bitflash — top-level build
#
#   make linux    build Bitflash-*-x86_64.AppImage
#   make windows  build Bitflash-*-windows.zip (from MSYS2 UCRT64)
#   make tests    build and run standalone unit tests
#   make checksums create SHA256SUMS for release assets
#   make verify-release TAG=v1.2.13
#   make clean    remove build artifacts

ROOT    := $(shell pwd)
NPROC   := $(shell nproc 2>/dev/null || echo 2)
SUDO    := $(shell [ "$$(id -u)" = "0" ] && echo "" || echo "sudo")
VERSION := 1.2.15

# ---- Linux ----------------------------------------------------------------

linux: deps-linux
	$(MAKE) -C src -f Makefile -j$(NPROC)
	strip src/bitflash
	$(MAKE) -f Makefile appimage
	$(MAKE) -f Makefile linux-node

# Headless node, no ImGui/GLFW/OpenGL. The GUI build needs libGL present at load
# time even when started with -nogui -- the dynamic loader resolves everything
# before main() runs, so the flag comes far too late. On a clean server, which is
# where a node most naturally lives, that is a hard failure. This binary has no
# such dependency and needs no FUSE either, so it drops onto a VPS and runs.
linux-node: deps-linux
	$(MAKE) -C src -f Makefile bitflash-node -j$(NPROC)
	strip src/bitflash-node
	cp src/bitflash-node bitflash-node-$(VERSION)-x86_64
	@echo "Built: bitflash-node-$(VERSION)-x86_64"

deps-linux: deps-apt deps-secp256k1 deps-randomx

deps-apt:
	@if command -v apt-get >/dev/null 2>&1; then \
	  $(SUDO) apt-get install -y build-essential cmake git pkg-config autoconf \
	    libtool libssl-dev libdb5.3++-dev libsodium-dev nlohmann-json3-dev \
	    libboost-system-dev libglfw3-dev libgl-dev python3-pil; \
	else \
	  echo "Not an apt system — install: g++ cmake git autoconf libtool"; \
	  echo "  libssl libdb++ libsodium nlohmann-json boost glfw3 opengl python3-pil"; \
	fi

deps-secp256k1:
	@if [ ! -f /usr/local/lib/libsecp256k1.a ]; then \
	  echo "==> building libsecp256k1"; \
	  rm -rf $(ROOT)/secp256k1-build; \
	  git clone --depth 1 https://github.com/bitcoin-core/secp256k1 $(ROOT)/secp256k1-build; \
	  cd $(ROOT)/secp256k1-build && ./autogen.sh && \
	  ./configure --enable-module-schnorrsig --enable-module-extrakeys \
	    --disable-shared --with-pic --disable-benchmark --disable-tests && \
	  make -j$(NPROC) && $(SUDO) make install && $(SUDO) ldconfig; \
	  echo "==> libsecp256k1 done"; \
	else \
	  echo "==> libsecp256k1 already installed"; \
	fi

deps-randomx:
	@if [ ! -f $(HOME)/RandomX/build/librandomx.a ]; then \
	  echo "==> building RandomX"; \
	  rm -rf $(HOME)/RandomX; \
	  git clone --depth 1 https://github.com/tevador/RandomX $(HOME)/RandomX; \
	  mkdir -p $(HOME)/RandomX/build; \
	  cd $(HOME)/RandomX/build && cmake .. -DCMAKE_BUILD_TYPE=Release && \
	  make -j$(NPROC) randomx; \
	  echo "==> RandomX done"; \
	else \
	  echo "==> RandomX already built"; \
	fi

appimage: src/bitflash
	@echo "==> building AppImage"
	@if [ ! -x /tmp/appimagetool ]; then \
	  wget -q "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage" \
	    -O /tmp/appimagetool && chmod +x /tmp/appimagetool; \
	fi
	@rm -rf /tmp/bitflash.AppDir
	@mkdir -p /tmp/bitflash.AppDir/usr/bin \
	          /tmp/bitflash.AppDir/usr/lib \
	          /tmp/bitflash.AppDir/usr/share/applications \
	          /tmp/bitflash.AppDir/usr/share/icons/hicolor/256x256/apps
	@cp src/bitflash /tmp/bitflash.AppDir/usr/bin/bitflash
	@printf '#!/bin/sh\nHERE="$$(dirname "$$(readlink -f "$$0")")"\nexport LD_LIBRARY_PATH="$$HERE/usr/lib:$$LD_LIBRARY_PATH"\nexec "$$HERE/usr/bin/bitflash" "$$@"\n' \
	  > /tmp/bitflash.AppDir/AppRun && chmod +x /tmp/bitflash.AppDir/AppRun
	@printf '[Desktop Entry]\nName=Bitflash\nExec=bitflash\nIcon=bitflash\nType=Application\nCategories=Finance;\n' \
	  > /tmp/bitflash.AppDir/bitflash.desktop
	@cp /tmp/bitflash.AppDir/bitflash.desktop \
	    /tmp/bitflash.AppDir/usr/share/applications/
	@python3 -c "\
from PIL import Image; \
ico = Image.open('src/rc/bitcoin.ico'); \
img = ico.convert('RGBA'); \
img.save('/tmp/bitflash.AppDir/bitflash.png'); \
import shutil; shutil.copy('/tmp/bitflash.AppDir/bitflash.png', \
'/tmp/bitflash.AppDir/usr/share/icons/hicolor/256x256/apps/bitflash.png')"
	@for lib in libsodium.so.23 libdb_cxx-5.3.so libglfw.so.3; do \
	  path=$$(ldconfig -p | grep " $$lib " | awk '{print $$NF}' | head -1); \
	  [ -z "$$path" ] && path=$$(find /usr/lib /lib -name "$$lib" 2>/dev/null | head -1); \
	  [ -n "$$path" ] && cp -L "$$path" /tmp/bitflash.AppDir/usr/lib/ && echo "  bundled $$lib" || echo "  missing $$lib"; \
	done
	@ARCH=x86_64 /tmp/appimagetool --no-appstream /tmp/bitflash.AppDir \
	  $(ROOT)/Bitflash-$(VERSION)-x86_64.AppImage 2>&1 | grep -E "^Built|^Error" || true
	@echo "Built: Bitflash-$(VERSION)-x86_64.AppImage"

# ---- Windows (MSYS2 UCRT64) -----------------------------------------------

deps-windows:
	pacman -S --noconfirm --needed \
	  mingw-w64-ucrt-x86_64-gcc \
	  mingw-w64-ucrt-x86_64-make \
	  mingw-w64-ucrt-x86_64-glfw \
	  mingw-w64-ucrt-x86_64-openssl \
	  mingw-w64-ucrt-x86_64-db \
	  mingw-w64-ucrt-x86_64-libsodium \
	  mingw-w64-ucrt-x86_64-nlohmann-json \
	  mingw-w64-ucrt-x86_64-boost \
	  mingw-w64-ucrt-x86_64-cmake \
	  autoconf automake libtool
	@if [ ! -f deps/lib/libsecp256k1.a ]; then \
	  rm -rf secp256k1-build; \
	  git clone --depth 1 https://github.com/bitcoin-core/secp256k1 secp256k1-build; \
	  cd secp256k1-build && ./autogen.sh && \
	  ./configure --prefix=$(ROOT)/deps \
	    --enable-module-schnorrsig --enable-module-extrakeys \
	    --disable-shared --with-pic --disable-benchmark --disable-tests && \
	  make install; \
	  echo "==> secp256k1 done"; \
	else \
	  echo "==> secp256k1 already built"; \
	fi
	@if [ ! -f RandomX/build/librandomx.a ]; then \
	  rm -rf RandomX; \
	  git clone --depth 1 https://github.com/tevador/RandomX; \
	  mkdir -p RandomX/build; \
	  cd RandomX/build && cmake .. -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release && \
	  make randomx; \
	  echo "==> RandomX done"; \
	else \
	  echo "==> RandomX already built"; \
	fi

windows: deps-windows
	cd src && make -f makefile.mingw
	@rm -rf Bitflash-$(VERSION)-windows
	@mkdir -p Bitflash-$(VERSION)-windows
	@cp src/bitflash.exe Bitflash-$(VERSION)-windows/Bitflash.exe
	@ldd src/bitflash.exe | grep ucrt64 | awk '{print $$3}' | \
	  xargs -I{} cp {} Bitflash-$(VERSION)-windows/ 2>/dev/null || true
	@zip -r Bitflash-$(VERSION)-windows.zip Bitflash-$(VERSION)-windows/
	@echo "Built: Bitflash-$(VERSION)-windows.zip"

# ---- Clean ----------------------------------------------------------------

clean:
	$(MAKE) -C src -f Makefile clean 2>/dev/null || true
	cd src && make -f makefile.mingw clean 2>/dev/null || true
	rm -f Bitflash-*.AppImage Bitflash-*.zip
	rm -rf Bitflash-*-windows

tests:
	$(MAKE) -C src -f Makefile tests

checksums:
	./scripts/make-release-checksums.sh

sign-checksums:
	./scripts/make-release-checksums.sh --sign $(if $(KEY),--local-user $(KEY),)

verify-release:
	./scripts/verify-release.sh $(if $(TAG),$(TAG),latest)

.PHONY: linux windows clean appimage \
        tests checksums sign-checksums verify-release \
        deps-linux deps-windows deps-apt deps-secp256k1 deps-randomx
