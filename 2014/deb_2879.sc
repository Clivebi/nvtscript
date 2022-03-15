if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702879" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-0017" );
	script_name( "Debian Security Advisory DSA 2879-1 (libssh - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-13 00:00:00 +0100 (Thu, 13 Mar 2014)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2879.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "libssh on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 0.4.5-3+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 0.5.4-1+deb7u1.

For the testing distribution (jessie), this problem has been fixed in
version 0.5.4-3.

For the unstable distribution (sid), this problem has been fixed in
version 0.5.4-3.

We recommend that you upgrade your libssh packages." );
	script_tag( name: "summary", value: "It was discovered that libssh, a tiny C SSH library, did not reset the
state of the PRNG after accepting a connection. A server mode
application that forks itself to handle incoming connections could see
its children sharing the same PRNG state, resulting in a cryptographic
weakness and possibly the recovery of the private key." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.4.5-3+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dbg", ver: "0.4.5-3+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dev", ver: "0.4.5-3+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-doc", ver: "0.4.5-3+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-4", ver: "0.5.4-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dbg", ver: "0.5.4-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-dev", ver: "0.5.4-1+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libssh-doc", ver: "0.5.4-1+deb7u1", rls: "DEB7" ) ) != NULL){
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

