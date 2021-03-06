if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702939" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746", "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3152" );
	script_name( "Debian Security Advisory DSA 2939-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-05-31 00:00:00 +0200 (Sat, 31 May 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2939.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 35.0.1916.114-1~deb7u2.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 35.0.1916.114-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in the chromium web browser.

CVE-2014-1743
cloudfuzzer discovered a use-after-free issue in the Blink/Webkit
document object model implementation.

CVE-2014-1744
Aaron Staple discovered an integer overflow issue in audio input
handling.

CVE-2014-1745
Atte Kettunen discovered a use-after-free issue in the Blink/Webkit
scalable vector graphics implementation.

CVE-2014-1746
Holger Fuhrmannek discovered an out-of-bounds read issue in the URL
protocol implementation for handling media.

CVE-2014-1747
packagesu discovered a cross-site scripting issue involving
malformed MHTML files.

CVE-2014-1748
Jordan Milne discovered a user interface spoofing issue.

CVE-2014-1749
The Google Chrome development team discovered and fixed multiple
issues with potential security impact.

CVE-2014-3152
An integer underflow issue was discovered in the v8 javascript
library." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromium", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-dbg", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-inspector", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-l10n", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "35.0.1916.114-1~deb7u2", rls: "DEB7" ) ) != NULL){
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

