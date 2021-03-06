if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703486" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2016-1622", "CVE-2016-1623", "CVE-2016-1624", "CVE-2016-1625", "CVE-2016-1626", "CVE-2016-1627", "CVE-2016-1628", "CVE-2016-1629" );
	script_name( "Debian Security Advisory DSA 3486-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-02-21 00:00:00 +0100 (Sun, 21 Feb 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3486.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 48.0.2564.116-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 48.0.2564.116-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2016-1622
It was discovered that a maliciously crafted extension could bypass
the Same Origin Policy.

CVE-2016-1623
Mariusz Mlynski discovered a way to bypass the Same Origin Policy.

CVE-2016-1624
lukezli discovered a buffer overflow issue in the Brotli library.

CVE-2016-1625
Jann Horn discovered a way to cause the Chrome Instant feature to
navigate to unintended destinations.

CVE-2016-1626
An out-of-bounds read issue was discovered in the openjpeg library.

CVE-2016-1627
It was discovered that the Developer Tools did not validate URLs.

CVE-2016-1628
An out-of-bounds read issue was discovered in the pdfium library.

CVE-2016-1629
A way to bypass the Same Origin Policy was discovered in Blink/WebKit,
along with a way to escape the chromium sandbox." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "48.0.2564.116-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "48.0.2564.116-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "48.0.2564.116-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "48.0.2564.116-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "48.0.2564.116-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

