if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703406" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2015-7183" );
	script_name( "Debian Security Advisory DSA 3406-1 (nspr - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-11-25 00:00:00 +0100 (Wed, 25 Nov 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3406.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "nspr on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy),
this problem has been fixed in version 2:4.9.2-1+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 2:4.10.7-1+deb8u1.

For the testing distribution (stretch), this problem has been fixed
in version 2:4.10.10-1.

For the unstable distribution (sid), this problem has been fixed in
version 2:4.10.10-1.

We recommend that you upgrade your nspr packages." );
	script_tag( name: "summary", value: "It was discovered that incorrect
memory allocation in the NetScape Portable Runtime library might result in
denial of service or the execution of arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnspr4:amd64", ver: "2:4.9.2-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4:i386", ver: "2:4.9.2-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d:amd64", ver: "2:4.9.2-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d:i386", ver: "2:4.9.2-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dbg:amd64", ver: "2:4.9.2-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dbg:i386", ver: "2:4.9.2-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dev", ver: "2:4.9.2-1+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4:amd64", ver: "2:4.10.10-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4:i386", ver: "2:4.10.10-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d:amd64", ver: "2:4.10.10-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d:i386", ver: "2:4.10.10-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dbg:amd64", ver: "2:4.10.10-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dbg:i386", ver: "2:4.10.10-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dev", ver: "2:4.10.10-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4:amd64", ver: "2:4.10.7-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4:i386", ver: "2:4.10.7-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d:amd64", ver: "2:4.10.7-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d:i386", ver: "2:4.10.7-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dbg:amd64", ver: "2:4.10.7-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dbg:i386", ver: "2:4.10.7-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dev", ver: "2:4.10.7-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

