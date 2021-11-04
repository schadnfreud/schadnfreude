#!/bin/bash
set -e
cd ../libsodium || cd ../../libsodium
UN=$(uname)
UNM=$(uname -m)
GITCOMMIT=$(git log -1 | head -1 | awk '{print $2}')
CACHEFNAME="$GITCOMMIT$UN$UNM"
export CFLAGS="-DED25519_NONDETERMINISTIC"
# make sure only one of these can run at once
exec 100>/tmp/buildls.lock || exit 1
flock 100 || exit 1

./autogen.sh
if [ "$1" != "" ] && echo "$1" | grep android ; then
	echo
	echo "libsodium building for host $1"
	echo "You may need to add something like the following in your ~/.cargo/config"
	cat <<EOF
[target.arm-linux-androideabi]
ar = "android-ndk-r19/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar"
linker = "android-ndk-r19/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi27-clang"

[target.aarch64-linux-android]
ar = "android-ndk-r19/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-ar"
linker = "android-ndk-r19/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android27-clang"
EOF
	if ls ~ | grep -E '^android-ndk-r[0-9]+$' ; then
		echo "Looks like you alreay have the NDK"
	else
		echo "Downloading NDK"
		pushd ~
		wget https://dl.google.com/android/repository/android-ndk-r19-linux-x86_64.zip
		unzip android-ndk-r19-linux-x86_64.zip
		rm android-ndk-r19-linux-x86_64.zip
		popd
		ls ~ | grep -E '^android-ndk-r[0-9]+$'
	fi
	NDKPATH=$(ls ~ | grep -E '^android-ndk-r[0-9]+$' | head -1)
	echo "NDKPATH $NDKPATH"
	# NDK calls it by a slightly different name
	if [ "$1" == arm-linux-androideabi ] || [ "$1" == armv7-linux-androideabi ] ; then
		CLANGVER=armv7a-linux-androideabi
	else
		CLANGVER="$1"
	fi
	ls ~/$NDKPATH/toolchains/llvm/prebuilt/*/bin/"$CLANGVER"*-clang
	echo
	export CC=$(ls ~/$NDKPATH/toolchains/llvm/prebuilt/*/bin/"$CLANGVER"*-clang | head -1)
	./configure --host=$1
else
	echo "Checking if we have this cached."
	if curl -f "https://www.scriptjunkie.us/upload.php?query=$CACHEFNAME" > cachecheck ; then
		echo "IT IS CACHED"
		mkdir -p ../relay/libsodium_$1/
		cp cachecheck ../relay/libsodium_$1/libsodium.a
		echo "DONE"
		exit 0
	fi
	echo "Not cached - libsodium building for native host"
	./configure
fi
make clean
make
RELAYFOLD=../relay/
if [ -d $RELAYFOLD ] ; then
  echo relay folder apparently found
else
  echo looking for relay folder
  RELAYFOLD=../schadnfreude/relay
  if [ -d $RELAYFOLD ] ; then
    echo relay folder now found
  else
    echo using old path
    RELAYFOLD=../schadenfreude/relay
  fi
fi
mkdir -p ../relay/libsodium_$1/
if [ "$1" != "" ] && echo "$1" | grep android ; then
	echo "Not native - not caching"
else
	echo "Caching"
	curl -F "file=@src/libsodium/.libs/libsodium.a" "https://www.scriptjunkie.us/upload.php?fname=$CACHEFNAME"
fi
cp src/libsodium/.libs/libsodium.a ../relay/libsodium_$1/
