if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703418" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-6788", "CVE-2015-6789", "CVE-2015-6790", "CVE-2015-6791" );
	script_name( "Debian Security Advisory DSA 3418-1 (chromium-browser - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-12-14 00:00:00 +0100 (Mon, 14 Dec 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3418.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "chromium-browser on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
these problems have been fixed in version 47.0.2526.80-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 47.0.2526.80-1.

We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been
discovered in the chromium web browser.

CVE-2015-6788
A type confusion issue was discovered in the handling of extensions.

CVE-2015-6789
cloudfuzzer discovered a use-after-free issue.

CVE-2015-6790
Inti De Ceukelaire discovered a way to inject HTML into
serialized web pages.

CVE-2015-6791
The chrome 47 development team found and fixed various issues
during internal auditing. Also multiple issues were fixed in
the v8 javascript library, version 4.7.80.23." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromedriver", ver: "47.0.2526.80-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "47.0.2526.80-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "47.0.2526.80-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "47.0.2526.80-1~deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "47.0.2526.80-1~deb8u1", rls: "DEB8" ) ) != NULL){
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

