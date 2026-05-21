# Homebrew formula for packetsonde.
#
# Tap-or-vendor install:
#   brew install --formula packaging/Formula/packetsonde.rb
#
# Or, when published to a tap:
#   brew tap billndotnet/packetsonde
#   brew install packetsonde
#
# Installs both the `packetsonde` CLI and the `packetsonded` agent.
# The launchd plist lands at /usr/local/etc/packetsonded/ and is NOT
# auto-loaded -- operators run `brew services start packetsonde` to
# enable it (or load the plist manually).

class Packetsonde < Formula
  desc     "CLI-first network infrastructure and security auditing toolkit"
  homepage "https://github.com/billndotnet/packetsonde"
  url      "https://github.com/billndotnet/packetsonde/archive/refs/tags/v1.6.tar.gz"
  # sha256 placeholder -- replaced at release time
  sha256   "PLACEHOLDER_REPLACE_AT_RELEASE"
  license  "PolyForm-Noncommercial-1.0.0"  # modified -- see LICENSE

  depends_on "cmake" => :build
  depends_on "pkg-config" => :build
  depends_on "openssl@3"
  depends_on "libpcap"
  depends_on "libedit"

  def install
    system "cmake", "-S", ".", "-B", "build",
                    "-DCMAKE_BUILD_TYPE=Release",
                    "-DCMAKE_INSTALL_PREFIX=#{prefix}",
                    *std_cmake_args
    system "cmake", "--build",   "build", "--parallel"
    system "cmake", "--install", "build"

    # Example config + launchd plist. Operators copy these to live
    # locations; brew installs to share to avoid clobbering local edits.
    (share/"packetsonde").install "packaging/packetsonded.toml"
    (share/"packetsonde").install "packaging/net.billn.packetsonded.plist"
  end

  service do
    run [opt_sbin/"packetsonded", "-c", etc/"packetsonded/packetsonded.toml"]
    keep_alive true
    log_path   var/"log/packetsonded/stdout.log"
    error_log_path var/"log/packetsonded/stderr.log"
    environment_variables PS_KEY_DIR: "#{etc}/packetsonded/keys"
  end

  def caveats
    <<~EOS
      Copy the example config + create the key directory:
        sudo mkdir -p #{etc}/packetsonded/keys/authorized
        sudo cp #{share}/packetsonde/packetsonded.toml #{etc}/packetsonded/
        sudo packetsonde key generate --name agent     # creates the agent identity

      Then start the daemon:
        brew services start packetsonde

      Discovery and --via are disabled by default. Edit #{etc}/packetsonded/packetsonded.toml
      to opt in. See packaging/packetsonded.toml for the full annotated example.
    EOS
  end

  test do
    system "#{bin}/packetsonde", "version"
  end
end
