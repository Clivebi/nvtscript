if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703015" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-5461" );
	script_name( "Debian Security Advisory DSA 3015-1 (lua5.1 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-09-01 00:00:00 +0200 (Mon, 01 Sep 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-3015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "lua5.1 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), this problem has been fixed in
version 5.1.5-4+deb7u1.

For the unstable distribution (sid), this problem has been fixed in
version 5.1.5-7.

We recommend that you upgrade your lua5.1 packages." );
	script_tag( name: "summary", value: "A heap-based overflow vulnerability was found in the way Lua, a
simple, extensible, embeddable programming language, handles varargs
functions with many fixed parameters called with few arguments,
leading to application crashes or, potentially, arbitrary code
execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "liblua5.1-0", ver: "5.1.5-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblua5.1-0-dbg", ver: "5.1.5-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "liblua5.1-0-dev", ver: "5.1.5-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lua5.1", ver: "5.1.5-4+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lua5.1-doc", ver: "5.1.5-4+deb7u1", rls: "DEB7" ) ) != NULL){
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

