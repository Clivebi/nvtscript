if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71824" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1954", "CVE-2012-1967" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:33:23 -0400 (Thu, 30 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2528-1 (icedove)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202528-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client.

CVE-2012-1948
Multiple unspecified vulnerabilities in the browser engine
were fixed.

CVE-2012-1950
The underlying browser engine allows address bar spoofing
through drag-and-drop.

CVE-2012-1954
A use-after-free vulnerability in the nsDocument::AdoptNode
function allows remote attackers to cause a denial of service
(heap memory corruption) or possibly execute arbitrary code.

CVE-2012-1967
An error in the implementation of the Javascript sandbox
allows execution of Javascript code with improper privileges
using javascript: URLs.

For the stable distribution (squeeze), these problems have been fixed
in version 3.0.11-1+squeeze12.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 10.0.6-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your icedove packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to icedove
announced via advisory DSA 2528-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "icedove", ver: "3.0.11-1+squeeze12", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "3.0.11-1+squeeze12", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "3.0.11-1+squeeze12", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "calendar-google-provider", ver: "10.0.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "calendar-timezones", ver: "10.0.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove", ver: "10.0.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dbg", ver: "10.0.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "icedove-dev", ver: "10.0.6-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceowl-extension", ver: "10.0.6-2", rls: "DEB7" ) ) != NULL){
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

