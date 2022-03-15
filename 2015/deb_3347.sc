if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703347" );
	script_version( "2020-01-21T07:42:39+0000" );
	script_cve_id( "CVE-2015-5230" );
	script_name( "Debian Security Advisory DSA 3347-1 (pdns - security update)" );
	script_tag( name: "last_modification", value: "2020-01-21 07:42:39 +0000 (Tue, 21 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-09-02 00:00:00 +0200 (Wed, 02 Sep 2015)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3347.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "pdns on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 3.4.1-4+deb8u3.

For the testing distribution (stretch) and unstable distribution
(sid), this problem has been fixed in version 3.4.6-1.

We recommend that you upgrade your pdns packages." );
	script_tag( name: "summary", value: "Pyry Hakulinen and Ashish Shakla at Automattic discovered that pdns,
an authoritative DNS server, was incorrectly processing some DNS
packets. This would enable a remote attacker to trigger a DoS by
sending specially crafted packets causing the server to crash." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "pdns-backend-geo", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-ldap", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-lmdb", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-lua", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-mydns", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-mysql", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-pgsql", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-pipe", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-remote", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-backend-sqlite3", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-server", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "pdns-server-dbg", ver: "3.4.1-4+deb8u3", rls: "DEB8" ) ) != NULL){
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
