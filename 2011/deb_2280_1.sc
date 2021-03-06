if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69989" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-2511", "CVE-2011-1486" );
	script_name( "Debian Security Advisory DSA 2280-1 (libvirt)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|5)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202280-1" );
	script_tag( name: "insight", value: "It was discovered that libvirt, a library for interfacing with different
virtualization systems, is prone to an integer overflow (CVE-2011-2511).
Additionally, the stable version is prone to a denial of service,
because its error reporting is not thread-safe (CVE-2011-1486).

For the stable distribution (squeeze), these problems have been fixed in
version 0.8.3-5+squeeze2.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.4.6-10+lenny2.

For the testing distribution (wheezy), these problems will fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 0.9.2-7)." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libvirt packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libvirt
announced via advisory DSA 2280-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "0.8.3-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-dev", ver: "0.8.3-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-doc", ver: "0.8.3-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0", ver: "0.8.3-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0-dbg", ver: "0.8.3-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libvirt", ver: "0.8.3-5+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "0.4.6-10+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-dev", ver: "0.4.6-10+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-doc", ver: "0.4.6-10+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0", ver: "0.4.6-10+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0-dbg", ver: "0.4.6-10+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-libvirt", ver: "0.4.6-10+lenny2", rls: "DEB5" ) ) != NULL){
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

