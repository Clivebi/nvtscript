if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703270" );
	script_version( "2019-11-27T15:23:21+0000" );
	script_cve_id( "CVE-2015-3165", "CVE-2015-3166", "CVE-2015-3167" );
	script_name( "Debian Security Advisory DSA 3270-1 (postgresql-9.4 - security update)" );
	script_tag( name: "last_modification", value: "2019-11-27 15:23:21 +0000 (Wed, 27 Nov 2019)" );
	script_tag( name: "creation_date", value: "2015-05-22 00:00:00 +0200 (Fri, 22 May 2015)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3270.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "postgresql-9.4 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), these problems have been fixed in
version 9.4.2-0+deb8u1.

For the testing distribution (stretch), these problems will be fixed
soon.

For the unstable distribution (sid), these problems have been fixed in
version 9.4.2-1.

We recommend that you upgrade your postgresql-9.4 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found in PostgreSQL-9.4, a SQL
database system.

CVE-2015-3165

(Remote crash)

SSL clients disconnecting just before the authentication timeout
expires can cause the server to crash.

CVE-2015-3166

(Information exposure)

The replacement implementation of snprintf() failed to check for
errors reported by the underlying system library calls. The main
case that might be missed is out-of-memory situations. In the worst
case this might lead to information exposure.

CVE-2015-3167

(Possible side-channel key exposure)

In contrib/pgcrypto, some cases of decryption with an incorrect key
could report other error message texts. Fix by using a
one-size-fits-all message." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libecpg-compat3", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg-dev", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libecpg6", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpgtypes3", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq-dev", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpq5", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-9.4-dbg", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-client-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-contrib-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-doc-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plperl-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-plpython3-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-pltcl-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "postgresql-server-dev-9.4", ver: "9.4.2-0+deb8u1", rls: "DEB8" ) ) != NULL){
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
