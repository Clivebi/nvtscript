if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702916" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-2892" );
	script_name( "Debian Security Advisory DSA 2916-1 (libmms - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-04-28 00:00:00 +0200 (Mon, 28 Apr 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2916.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libmms on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.6-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 0.6.2-3+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 0.6.2-4.

We recommend that you upgrade your libmms packages." );
	script_tag( name: "summary", value: "Alex Chapman discovered that a buffer overflow in processing MMS over
HTTP
messages could result in the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmms-dev", ver: "0.6-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmms0", ver: "0.6-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmms-dev", ver: "0.6.2-3+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmms0", ver: "0.6.2-3+deb7u1", rls: "DEB7" ) ) != NULL){
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

