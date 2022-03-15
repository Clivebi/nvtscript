if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702820" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2013-5607" );
	script_name( "Debian Security Advisory DSA 2820-1 (nspr - integer overflow)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-17 00:00:00 +0100 (Tue, 17 Dec 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2820.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "nspr on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 4.8.6-1+squeeze1.

For the stable distribution (wheezy), this problem has been fixed in
version 2:4.9.2-1+deb7u1.

For the testing distribution (jessie), and the unstable distribution
(sid), this problem has been fixed in version 2:4.10.2-1.

We recommend that you upgrade your nspr packages." );
	script_tag( name: "summary", value: "It was discovered that NSPR, Netscape Portable Runtime library, could
crash an application using the library when parsing a certificate that
causes an integer overflow. This flaw only affects 64-bit systems." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnspr4-0d", ver: "4.8.6-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d-dbg", ver: "4.8.6-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dev", ver: "4.8.6-1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4", ver: "2:4.9.2-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-0d", ver: "2:4.9.2-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dbg", ver: "2:4.9.2-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libnspr4-dev", ver: "2:4.9.2-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

