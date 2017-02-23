require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Smartmontools < AbstractOsqueryFormula
  desc "SMART hard drive monitoring; Fork with smartctl exposed as a static library"
  homepage "https://www.smartmontools.org/"
  url "https://github.com/allanliu/smartmontools/archive/v0.1.0.tar.gz"
  sha256 "280cd7a1eef57079db0747d52599a530f06ddf1d7b57da494fc85b879c4e0212"


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
