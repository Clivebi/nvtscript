if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703279" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-4335" );
	script_name( "Debian Security Advisory DSA 3279-1 (redis - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-06-06 00:00:00 +0200 (Sat, 06 Jun 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3279.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "redis on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2:2.8.17-1+deb8u1.

For the testing distribution (stretch), this problem will be fixed
in version 2:3.0.2-1.

For the unstable distribution (sid), this problem has been fixed in
version 2:3.0.2-1.

We recommend that you upgrade your redis packages." );
	script_tag( name: "summary", value: "It was discovered that redis, a persistent key-value database, could
execute insecure Lua bytecode by way of the EVAL command. This could
allow remote attackers to break out of the Lua sandbox and execute
arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "redis-sentinel", ver: "2:3.0.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "redis-server", ver: "2:3.0.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "redis-tools", ver: "2:3.0.2-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "redis-server", ver: "2:2.8.17-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "redis-tools", ver: "2:2.8.17-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

