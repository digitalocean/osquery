require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Smartmontools < AbstractOsqueryFormula
  desc "SMART hard drive monitoring; Fork with smartctl exposed as a static library"
  homepage "https://www.smartmontools.org/"
  url "https://github.com/allanliu/smartmontools/archive/v0.2.1.tar.gz"
  sha256 "8529d0f4f87ff3c73a96215f75110800bcc25982b69f06d3e82a24e10e625f47"


  depends_on "automake" => :build
  depends_on "autoconf" => :build
  depends_on "libtool" => :build

  def install
    system "./autogen.sh"

    ENV.append "CXXFLAGS", "-fPIC"
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end
end
