if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69744" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-1292", "CVE-2011-1293", "CVE-2011-1440", "CVE-2011-1444", "CVE-2011-1797", "CVE-2011-1799" );
	script_name( "Debian Security Advisory DSA 2245-1 (chromium-browser)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202245-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in the Chromium browser.
The Common Vulnerabilities and Exposures project identifies the
following problems:


CVE-2011-1292

Use-after-free vulnerability in the frame-loader implementation in Google
Chrome allows remote attackers to cause a denial of service or possibly
have unspecified other impact via unknown vectors.


CVE-2011-1293

Use-after-free vulnerability in the HTMLCollection implementation in Google
Chrome allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors.


CVE-2011-1440

Use-after-free vulnerability in Google Chrome allows remote attackers to cause
a denial of service or possibly have unspecified other impact via vectors
related to the ruby element and Cascading Style Sheets (CSS) token sequences.


CVE-2011-1444

Race condition in the sandbox launcher implementation in Google Chrome on
Linux allows remote attackers to cause a denial of service or possibly have
unspecified other impact via unknown vectors.


CVE-2011-1797

Google Chrome does not properly render tables, which allows remote attackers
to cause a denial of service or possibly have unspecified other impact via
unknown vectors that lead to a stale pointer.


CVE-2011-1799

Google Chrome does not properly perform casts of variables during interaction
with the WebKit engine, which allows remote attackers to cause a denial of
service or possibly have unspecified other impact via unknown vectors.



For the stable distribution (squeeze), these problems have been fixed in
version 6.0.472.63~r59945-5+squeeze5.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 11.0.696.68~r84545-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your chromium-browser packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to chromium-browser
announced via advisory DSA 2245-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "chromium-browser", ver: "6.0.472.63~r59945-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-dbg", ver: "6.0.472.63~r59945-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-inspector", ver: "6.0.472.63~r59945-5+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "chromium-browser-l10n", ver: "6.0.472.63~r59945-5+squeeze5", rls: "DEB6" ) ) != NULL){
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

