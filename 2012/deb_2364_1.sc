if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70576" );
	script_cve_id( "CVE-2011-4613" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:34:39 -0500 (Sat, 11 Feb 2012)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2364-1 (xorg)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202364-1" );
	script_tag( name: "insight", value: "The Debian X wrapper enforces that the X server can only be started from
a console. vladz discovered that this wrapper could be bypassed.

The oldstable distribution (lenny) is not affected.

For the stable distribution (squeeze), this problem has been fixed in
version 7.5+8+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1:7.6+10." );
	script_tag( name: "solution", value: "We recommend that you upgrade your xorg packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to xorg
announced via advisory DSA 2364-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libglu1-xorg", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libglu1-xorg-dev", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "x11-common", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xbase-clients", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xlibmesa-gl", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xlibmesa-gl-dev", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xlibmesa-glu", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xorg", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xorg-dev", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-input-all", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xserver-xorg-video-all", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xutils", ver: "1:7.5+8+squeeze1", rls: "DEB6" ) ) != NULL){
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

