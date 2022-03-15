if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702841" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0977" );
	script_name( "Debian Security Advisory DSA 2841-1 (movabletype-opensource - cross-site scripting)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-01-11 00:00:00 +0100 (Sat, 11 Jan 2014)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2841.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "movabletype-opensource on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 4.3.8+dfsg-0+squeeze4.

For the stable distribution (wheezy), this problem has been fixed in
version 5.1.4+dfsg-4+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 5.2.9+dfsg-1.

We recommend that you upgrade your movabletype-opensource packages." );
	script_tag( name: "summary", value: "A cross-site scripting vulnerability was discovered in the rich text
editor of the Movable Type blogging engine." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "movabletype-opensource", ver: "4.3.8+dfsg-0+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-core", ver: "4.3.8+dfsg-0+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-zemanta", ver: "4.3.8+dfsg-0+squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-opensource", ver: "5.1.4+dfsg-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-core", ver: "5.1.4+dfsg-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "movabletype-plugin-zemanta", ver: "5.1.4+dfsg-4+deb7u1", rls: "DEB7" ) ) != NULL){
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

