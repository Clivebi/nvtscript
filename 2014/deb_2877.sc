if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702877" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-2323", "CVE-2014-2324" );
	script_name( "Debian Security Advisory DSA 2877-1 (lighttpd - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-12 00:00:00 +0100 (Wed, 12 Mar 2014)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2877.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "lighttpd on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), these problems have been fixed in
version 1.4.28-2+squeeze1.6.

For the stable distribution (wheezy), these problems have been fixed in
version 1.4.31-4+deb7u3.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in
version 1.4.33-1+nmu3.

We recommend that you upgrade your lighttpd packages." );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in the lighttpd web server.

CVE-2014-2323
Jann Horn discovered that specially crafted host names can be used
to inject arbitrary MySQL queries in lighttpd servers using the
MySQL virtual hosting module (mod_mysql_vhost).

This only affects installations with the lighttpd-mod-mysql-vhost
binary package installed and in use.

CVE-2014-2324
Jann Horn discovered that specially crafted host names can be used
to traverse outside of the document root under certain situations
in lighttpd servers using either the mod_mysql_vhost, mod_evhost,
or mod_simple_vhost virtual hosting modules.

Servers not using these modules are not affected." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "lighttpd", ver: "1.4.28-2+squeeze1.6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-doc", ver: "1.4.28-2+squeeze1.6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-cml", ver: "1.4.28-2+squeeze1.6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-magnet", ver: "1.4.28-2+squeeze1.6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-mysql-vhost", ver: "1.4.28-2+squeeze1.6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-trigger-b4-dl", ver: "1.4.28-2+squeeze1.6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-webdav", ver: "1.4.28-2+squeeze1.6", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd", ver: "1.4.31-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-doc", ver: "1.4.31-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-cml", ver: "1.4.31-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-magnet", ver: "1.4.31-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-mysql-vhost", ver: "1.4.31-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-trigger-b4-dl", ver: "1.4.31-4+deb7u3", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-webdav", ver: "1.4.31-4+deb7u3", rls: "DEB7" ) ) != NULL){
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

