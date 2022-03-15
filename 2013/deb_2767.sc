if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702767" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-4359" );
	script_name( "Debian Security Advisory DSA 2767-1 (proftpd-dfsg - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-29 00:00:00 +0200 (Sun, 29 Sep 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2767.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "proftpd-dfsg on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 1.3.3a-6squeeze7.

For the stable distribution (wheezy), this problem has been fixed in
version 1.3.4a-5+deb7u1.

For the testing (jessie) and unstable (sid) distributions, this problem will
be fixed soon.

We recommend that you upgrade your proftpd-dfsg packages." );
	script_tag( name: "summary", value: "Kingcope discovered that the mod_sftp and mod_sftp_pam modules of
proftpd, a powerful modular FTP/SFTP/FTPS server, are not properly
validating input, before making pool allocations. An attacker can
use this flaw to conduct denial of service attacks against the system
running proftpd (resource exhaustion)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.3a-6squeeze7", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.4a-5+deb7u1", rls: "DEB7" ) ) != NULL){
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

