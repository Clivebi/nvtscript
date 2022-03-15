if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71237" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0458", "CVE-2012-0461" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-04-30 07:54:25 -0400 (Mon, 30 Apr 2012)" );
	script_name( "Debian Security Advisory DSA 2433-1 (iceweasel)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202433-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Iceweasel, a web browser
based on Firefox. The included XULRunner library provides rendering
services for several other applications included in Debian.

CVE-2012-0455

Soroush Dalili discovered that a cross-site scripting countermeasure
related to Javascript URLs could be bypassed.

CVE-2012-0456

Atte Kettunen discovered an out of bounds read in the SVG Filters,
resulting in memory disclosure.

CVE-2012-0458

Mariusz Mlynski discovered that privileges could be escalated through
a Javascript URL as the home page.

CVE-2012-0461

Bob Clary discovered memory corruption bugs, which may lead to the
execution of arbitrary code.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.16-13.

For the unstable distribution (sid), this problem has been fixed in
version 10.0.3esr-1.

For the experimental distribution, this problem has been fixed in
version 11.0-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your iceweasel packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to iceweasel
announced via advisory DSA 2433-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceweasel", ver: "3.5.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-dbg", ver: "3.5.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs-dev", ver: "1.9.1.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs2d", ver: "1.9.1.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs2d-dbg", ver: "1.9.1.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spidermonkey-bin", ver: "1.9.1.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9.1", ver: "1.9.1.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9.1-dbg", ver: "1.9.1.16-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.1.16-14", rls: "DEB6" ) ) != NULL){
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

