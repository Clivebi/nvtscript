if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703660" );
	script_version( "2021-09-20T12:48:38+0000" );
	script_cve_id( "CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5167" );
	script_name( "Debian Security Advisory DSA 3660-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:48:38 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-09-05 00:00:00 +0200 (Mon, 05 Sep 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3660.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
    these problems have been fixed in version 53.0.2785.89-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 53.0.2785.89-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
    discovered in the chromium web browser.

CVE-2016-5147
A cross-site scripting issue was discovered.

CVE-2016-5148
Another cross-site scripting issue was discovered.

CVE-2016-5149
Max Justicz discovered a script injection issue in extension handling.

CVE-2016-5150
A use-after-free issue was discovered in Blink/Webkit.

CVE-2016-5151
A use-after-free issue was discovered in the pdfium library.

CVE-2016-5152
GiWan Go discovered a heap overflow issue in the pdfium library.

CVE-2016-5153
Atte Kettunen discovered a use-after-destruction issue.

CVE-2016-5154
A heap overflow issue was discovered in the pdfium library.

CVE-2016-5155
An address bar spoofing issue was discovered.

CVE-2016-5156
jinmo123 discovered a use-after-free issue.

CVE-2016-5157
A heap overflow issue was discovered in the pdfium library.

CVE-2016-5158
GiWan Go discovered a heap overflow issue in the pdfium library.

CVE-2016-5159
GiWan Go discovered another heap overflow issue in the pdfium library.

CVE-2016-5160
l33terally discovered an extensions resource bypass.

CVE-2016-5161
A type confusion issue was discovered.

CVE-2016-5162
Nicolas Golubovic discovered an extensions resource bypass.

CVE-2016-5163
Rafay Baloch discovered an address bar spoofing issue.

CVE-2016-5164
A cross-site scripting issue was discovered in the developer tools.

CVE-2016-5165
Gregory Panakkal discovered a script injection issue in the developer
tools.

CVE-2016-5166
Gregory Panakkal discovered an issue with the Save Page As feature.

CVE-2016-5167
The chrome development team found and fixed various issues during
internal auditing." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "53.0.2785.89-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "53.0.2785.89-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "53.0.2785.89-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "53.0.2785.89-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "53.0.2785.89-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

