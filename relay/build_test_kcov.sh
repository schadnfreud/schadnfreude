#!/bin/bash
set -e
ip a || ifconfig -a || echo no ip stuff

#start musl build in background
(rustup target add x86_64-unknown-linux-musl && nice cargo build --release --bin schadnfreude --target=x86_64-unknown-linux-musl) &
RELEASEBUILDPROC=$!

#see if we have libsodium cached. If not then block on the last build so the builds don't conflict
pushd ../libsodium || pushd ../../libsodium
UN=$(uname)
UNM=$(uname -m)
GITCOMMIT=$(git log -1 | head -1 | awk '{print $2}')
CACHEFNAME="$GITCOMMIT$UN$UNM"
if [ "$1" != "" ] && echo "$1" | grep android ; then
	echo "waiting for cache - android"
	wait $RELEASEBUILDPROC || echo "nowait"
else
	echo "Checking if we have this cached."
	if curl -f "https://www.scriptjunkie.us/upload.php?query=$CACHEFNAME" > cachecheck ; then
		echo "cache hit allowing parallel build"
	else
		echo "waiting for cache - native"
		wait $RELEASEBUILDPROC || echo "nowait"
	fi
fi
popd

echo "Getting JRE and closure compiler"
apt-get install -yqq default-jre-headless &
GETJREPROC=$!

CLOSUREVERSION=$(wget -q -O - https://repo1.maven.org/maven2/com/google/javascript/closure-compiler/maven-metadata.xml | grep latest | awk -F'>' '{print $2}' | awk -F'<' '{print $1}')
echo "Closure version $CLOSUREVERSION"
CLOSUREURL="https://repo1.maven.org/maven2/com/google/javascript/closure-compiler/$CLOSUREVERSION/closure-compiler-$CLOSUREVERSION.jar"
echo "Closure URL $CLOSUREURL"
wget -qO ../closure-compiler.jar "$CLOSUREURL"
chmod a+x jscompile.sh
wait $GETJREPROC || echo "nowait"
nice ./jscompile.sh

echo "Building test config"
# ensure kcov is there and cargo test is there
kcov --version && nice cargo test --no-run || (
nice cargo test --no-run &
TESTBUILD=$!
echo "Attempting to acquire kcov..."
mkdir /tmp/kcov
pushd /tmp/kcov
git clone https://github.com/SimonKagstrom/kcov.git
cd kcov
git checkout c18c77531f3fc00440571a9a04dd33ee4fcd4c39
cd ..
mkdir kcbuild
cd kcbuild
cmake ../kcov/
nice make
make install
popd
wait $TESTBUILD || echo "nowait"
)

#we'll need jq later
apt-get install -yqq jq &
JQINST=$!
# ensure release target is added. You can download that while kcov runs
mkdir /tmp/kcovout
export RUST_BACKTRACE=1
nice kcov --include-pattern=relay/src /tmp/kcovout target/debug/deps/$(ls -tr target/debug/deps/ | grep schadnfreude- | grep -v \\. | head -1) --nocapture

wait $JQINST || echo "nowait"

wait $RELEASEBUILDPROC || echo "norbwait"
cp target/x86_64-unknown-linux-musl/release/schadnfreude target/x86_64-unknown-linux-musl/release/schadnfreudestripped
strip target/x86_64-unknown-linux-musl/release/schadnfreudestripped

pushd /tmp/kcovout
TOTALLINES=$(cat schadnfreude-*/coverage.json | grep relay/src | sed 's/},/}/' | jq '.total_lines' | sed 's/"//g' | paste -sd+ - | bc)
COVEREDLINES=$(cat schadnfreude-*/coverage.json | grep relay/src | sed 's/},/}/' | jq '.covered_lines' | sed 's/"//g' | paste -sd+ - | bc)
PERCENTG=$(echo "scale = 2; $COVEREDLINES * 100 / $TOTALLINES" | bc)
echo "CODE COVERAGE $PERCENTG%"
popd
tar -C /tmp/kcovout -cvJ . > kcovout.tar.xz


wait $RELEASEBUILDPROC || echo "nowait"
