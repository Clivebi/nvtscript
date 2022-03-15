if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70240" );
	script_version( "2020-05-26T08:07:04+0000" );
	script_tag( name: "last_modification", value: "2020-05-26 08:07:04 +0000 (Tue, 26 May 2020)" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-2359", "CVE-2011-2800", "CVE-2011-2818" );
	script_name( "Debian Security Advisory DSA 2307-1 (chromium-browser)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202307-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the Chromium browser.
The Common Vulnerabilities and Exposures project identifies
the following problems:

CVE-2011-2818

Use-after-free vulnerability in Google Chrome allows remote attackers to
cause a denial of service or possibly have unspecified other impact via
vectors related to display box rendering.


CVE-2011-2800

Google Chrome before allows remote attackers to obtain potentially sensitive
information about client-side redirect targets via a crafted web site.


CVE-2011-2359

Google Chrome does not properly track line boxes during rendering, which
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors that lead to a stale pointer.


Several unauthorised SSL certificates have been found in the wild issued
for the DigiNotar Certificate Authority, obtained through a security
compromise with said company.
This update blacklists SSL certificates issued by DigiNotar-controlled
intermediate CAs used by the Dutch PKIoverheid program.


For the stable distribution (squeeze), this problem has been fixed in
version 6.0.472.63~r59945-5+squeeze6.

For the testing distribution (wheezy), this problem has been fixed in
version 13.0.782.220~r99552-1.

For the unstable distribution (sid), this problem has been fixed in
version 13.0.782.220~r99552-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to chromium-browser
announced via advisory DSA 2307-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromium-browser", ver: "6.0.472.63~r59945-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-dbg", ver: "6.0.472.63~r59945-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-inspector", ver: "6.0.472.63~r59945-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-l10n", ver: "6.0.472.63~r59945-5+squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-dbg", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-inspector", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-l10n", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-dbg", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-inspector", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-l10n", ver: "13.0.782.220~r99552-1", rls: "DEB7" ) ) != NULL){
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

