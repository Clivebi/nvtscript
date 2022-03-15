if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703180" );
	script_version( "$Revision: 14278 $" );
	script_name( "Debian Security Advisory DSA 3180-1 (libarchive - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-03-05 00:00:00 +0100 (Thu, 05 Mar 2015)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3180.html" );
	script_cve_id( "CVE-2015-2304" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libarchive on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 3.0.4-3+wheezy1.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 3.1.2-11.

For the unstable distribution (sid), this problem has been fixed in
version 3.1.2-11.

We recommend that you upgrade your libarchive packages." );
	script_tag( name: "summary", value: "Alexander Cherepanov discovered that
bsdcpio, an implementation of the cpio  program part of the libarchive project,
is susceptible to a directory traversal vulnerability via absolute paths." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "bsdcpio", ver: "3.0.4-3+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "bsdtar", ver: "3.0.4-3+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:amd64", ver: "3.0.4-3+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive-dev:i386", ver: "3.0.4-3+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive12:i386", ver: "3.0.4-3+wheezy1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libarchive12:amd64", ver: "3.0.4-3+wheezy1", rls: "DEB7" ) ) != NULL){
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

