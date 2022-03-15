if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702649" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2013-1427" );
	script_name( "Debian Security Advisory DSA 2649-1 (lighttpd - fixed socket name in world-writable directory)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-15 00:00:00 +0100 (Fri, 15 Mar 2013)" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2649.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "lighttpd on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.4.28-2+squeeze1.3.

For the testing distribution (wheezy), this problem has been fixed in
version 1.4.31-4.

For the unstable distribution (sid), this problem has been fixed in
version 1.4.31-4.

We recommend that you upgrade your lighttpd packages." );
	script_tag( name: "summary", value: "Stefan Bühler discovered that the Debian specific configuration file for
lighttpd webserver FastCGI PHP support used a fixed socket name in the
world-writable /tmp directory. A symlink attack or a race condition could be
exploited by a malicious user on the same machine to take over the PHP control
socket and for example force the webserver to use a different PHP version.

As the fix is in a configuration file lying in /etc, the update won't be
enforced if the file has been modified by the administrator. In that case, care
should be taken to manually apply the fix." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "lighttpd", ver: "1.4.28-2+squeeze1.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-doc", ver: "1.4.28-2+squeeze1.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-cml", ver: "1.4.28-2+squeeze1.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-magnet", ver: "1.4.28-2+squeeze1.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-mysql-vhost", ver: "1.4.28-2+squeeze1.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-trigger-b4-dl", ver: "1.4.28-2+squeeze1.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-webdav", ver: "1.4.28-2+squeeze1.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd", ver: "1.4.31-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-doc", ver: "1.4.31-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-cml", ver: "1.4.31-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-magnet", ver: "1.4.31-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-mysql-vhost", ver: "1.4.31-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-trigger-b4-dl", ver: "1.4.31-4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "lighttpd-mod-webdav", ver: "1.4.31-4", rls: "DEB7" ) ) != NULL){
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

