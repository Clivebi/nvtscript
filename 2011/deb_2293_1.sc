if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70229" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-2895" );
	script_name( "Debian Security Advisory DSA 2293-1 (libxfont)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(5|6)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202293-1" );
	script_tag( name: "insight", value: "Tomas Hoger found a buffer overflow in the X.Org libXfont library,
which may allow for a local privilege escalation through crafted
font files.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.3.3-2.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.1-3.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.4-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libxfont packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libxfont
announced via advisory DSA 2293-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1:1.3.3-2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.3.3-2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1-dbg", ver: "1:1.3.3-2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont-dev", ver: "1:1.4.1-3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1", ver: "1:1.4.1-3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1-dbg", ver: "1:1.4.1-3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libxfont1-udeb", ver: "1:1.4.1-2", rls: "DEB6" ) ) != NULL){
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

