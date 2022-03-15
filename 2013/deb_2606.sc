if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702606" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-6095" );
	script_name( "Debian Security Advisory DSA 2606-1 (proftpd-dfsg - symlink race)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-13 00:00:00 +0100 (Sun, 13 Jan 2013)" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2606.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "proftpd-dfsg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.3.3a-6squeeze6.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1.3.4a-3.

We recommend that you upgrade your proftpd-dfsg packages." );
	script_tag( name: "summary", value: "It has been discovered that in ProFTPd, an FTP server, an attacker on
the same physical host as the server may be able to perform a symlink
attack allowing to elevate privileges in some configurations." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.3a-6squeeze6", rls: "DEB6" ) ) != NULL){
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

