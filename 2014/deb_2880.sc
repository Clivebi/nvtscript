if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702880" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-4238", "CVE-2014-1912" );
	script_name( "Debian Security Advisory DSA 2880-1 (python2.7 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-17 00:00:00 +0100 (Mon, 17 Mar 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2880.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "python2.7 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 2.7.3-6+deb7u2.

For the unstable distribution (sid), these problems have been fixed in
version 2.7.6-7.

We recommend that you upgrade your python2.7 packages." );
	script_tag( name: "summary", value: "Multiple security issues were discovered in Python:

CVE-2013-4238
Ryan Sleevi discovered that NULL characters in the subject alternate
names of SSL cerficates were parsed incorrectly.

CVE-2014-1912
Ryan Smith-Roberts discovered a buffer overflow in the
socket.recvfrom_into() function." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "idle-python2.7", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpython2.7", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python2.7", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python2.7-dbg", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python2.7-dev", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python2.7-doc", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python2.7-examples", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python2.7-minimal", ver: "2.7.3-6+deb7u2", rls: "DEB7" ) ) != NULL){
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

