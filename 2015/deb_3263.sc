if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703263" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-3306" );
	script_name( "Debian Security Advisory DSA 3263-1 (proftpd-dfsg - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-05-19 00:00:00 +0200 (Tue, 19 May 2015)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3263.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "proftpd-dfsg on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution
(wheezy), this problem has been fixed in version 1.3.4a-5+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 1.3.5-1.1+deb8u1.

For the testing distribution (stretch) and unstable distribution
(sid), this problem has been fixed in version 1.3.5-2.

We recommend that you upgrade your proftpd-dfsg packages." );
	script_tag( name: "summary", value: "Vadim Melihow discovered that in
proftpd-dfsg, an FTP server, the mod_copy module allowed unauthenticated users
to copy files around on the server, and possibly to execute arbitrary code." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "proftpd-basic", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-dev", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-doc", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-ldap", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-mysql", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-odbc", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-pgsql", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "proftpd-mod-sqlite", ver: "1.3.4a-5+deb7u3", rls: "DEB7" ) ) != NULL){
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

