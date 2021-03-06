if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702915" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0471" );
	script_name( "Debian Security Advisory DSA 2915-1 (dpkg - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-28 00:00:00 +0200 (Mon, 28 Apr 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2915.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "dpkg on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.15.9.

For the stable distribution (wheezy), this problem has been fixed in
version 1.16.13.

For the testing distribution (jessie), this problem will be fixed soon.

For the unstable distribution (sid), this problem will be fixed in
version 1.17.8.

We recommend that you upgrade your dpkg packages." );
	script_tag( name: "summary", value: "Jakub Wilk discovered that dpkg did not correctly parse C-style
filename quoting, allowing for paths to be traversed when unpacking a
source package - leading to the creation of files outside the directory
of the source being unpacked.

The update to the stable distribution (wheezy) incorporates
non-security changes that were targeted for the point release 7.5." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dpkg", ver: "1.15.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dpkg-dev", ver: "1.15.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dselect", ver: "1.15.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdpkg-dev", ver: "1.15.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdpkg-perl", ver: "1.15.9", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dpkg", ver: "1.16.13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dpkg-dev", ver: "1.16.13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dselect", ver: "1.16.13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdpkg-dev", ver: "1.16.13", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdpkg-perl", ver: "1.16.13", rls: "DEB7" ) ) != NULL){
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

