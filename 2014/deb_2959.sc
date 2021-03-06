if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702959" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3156", "CVE-2014-3157" );
	script_name( "Debian Security Advisory DSA 2959-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-06-14 00:00:00 +0200 (Sat, 14 Jun 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2959.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 35.0.1916.153-1~deb7u1.

For the testing (jessie) and unstable (sid) distribution, these problems
have been fixed in version 35.0.1916.153-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the chromium web browser.

CVE-2014-3154
Collin Payne discovered a use-after-free issue in the filesystem API.

CVE-2014-3155
James March, Daniel Sommermann, and Alan Frindell discovered several
out-of-bounds read issues in the SPDY protocol implementation.

CVE-2014-3156
Atte Kettunen discovered a buffer overflow issue in bitmap handling
in the clipboard implementation.

CVE-2014-3157
A heap-based buffer overflow issue was discovered in chromium's
ffmpeg media filter.

In addition, this version corrects a regression in the previous update.
Support for older i386 processors had been dropped. This functionality
is now restored." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromium", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-dbg", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-inspector", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-l10n", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "35.0.1916.153-1~deb7u1", rls: "DEB7" ) ) != NULL){
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

