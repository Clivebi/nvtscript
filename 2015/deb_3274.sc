if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703274" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3456" );
	script_name( "Debian Security Advisory DSA 3274-1 (virtualbox - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-28 00:00:00 +0200 (Thu, 28 May 2015)" );
	script_tag( name: "cvss_base", value: "7.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3274.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "virtualbox on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), this problem has been fixed in version 4.1.18-dfsg-2+deb7u5.

For the stable distribution (jessie), this problem has been fixed in
version 4.3.18-dfsg-3+deb8u2.

For the unstable distribution (sid), this problem has been fixed in
version 4.3.28-dfsg-1.

We recommend that you upgrade your virtualbox packages." );
	script_tag( name: "summary", value: "Jason Geffner discovered a buffer
overflow in the emulated floppy disk drive, resulting in potential privilege
escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed
software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "virtualbox", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dbg", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-dkms", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-fuse", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-dkms", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-source", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-utils", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-guest-x11", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dbg", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-dkms", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-fuse", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-dkms", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-source", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-utils", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-guest-x11", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-qt", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-ose-source", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-qt", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "virtualbox-source", ver: "4.1.18-dfsg-2+deb7u5", rls: "DEB7" ) ) != NULL){
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

