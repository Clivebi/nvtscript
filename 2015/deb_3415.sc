if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703415" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2015-1302", "CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786" );
	script_name( "Debian Security Advisory DSA 3415-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2015-12-09 00:00:00 +0100 (Wed, 09 Dec 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3415.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 47.0.2526.73-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 47.0.2526.73-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2015-1302
Rub Wu discovered an information leak in the pdfium library.

CVE-2015-6764
Guang Gong discovered an out-of-bounds read issue in the v8
javascript library.

CVE-2015-6765
A use-after-free issue was discovered in AppCache.

CVE-2015-6766
A use-after-free issue was discovered in AppCache.

CVE-2015-6767
A use-after-free issue was discovered in AppCache.

CVE-2015-6768
Mariusz Mlynski discovered a way to bypass the Same Origin
Policy.

CVE-2015-6769
Mariusz Mlynski discovered a way to bypass the Same Origin
Policy.

CVE-2015-6770
Mariusz Mlynski discovered a way to bypass the Same Origin
Policy.

CVE-2015-6771
An out-of-bounds read issue was discovered in the v8
javascript library.

CVE-2015-6772
Mariusz Mlynski discovered a way to bypass the Same Origin
Policy.

CVE-2015-6773
cloudfuzzer discovered an out-of-bounds read issue in the
skia library.

CVE-2015-6774
A use-after-free issue was found in extensions binding.

CVE-2015-6775
Atte Kettunen discovered a type confusion issue in the pdfium
library.

CVE-2015-6776
Hanno Bck discovered an out-of-bounds access issue in the
openjpeg library, which is used by pdfium.

CVE-2015-6777
Long Liu found a use-after-free issue.

CVE-2015-6778
Karl Skomski found an out-of-bounds read issue in the pdfium
library.

CVE-2015-6779Til Jasper Ullrich discovered that the pdfium library does
not sanitize chrome:
URLs.

CVE-2015-6780
Khalil Zhani discovered a use-after-free issue.

CVE-2015-6781
miaubiz discovered an integer overflow issue in the sfntly
library.

CVE-2015-6782
Luan Herrera discovered a URL spoofing issue.

CVE-2015-6784
Inti De Ceukelaire discovered a way to inject HTML into
serialized web pages.

CVE-2015-6785
Michael Ficarra discovered a way to bypass the Content
Security Policy.

CVE-2015-6786
Michael Ficarra discovered another way to bypass the Content
Security Policy." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "47.0.2526.73-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "47.0.2526.73-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "47.0.2526.73-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "47.0.2526.73-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "47.0.2526.73-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

