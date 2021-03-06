if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702990" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2014-3537", "CVE-2014-5029", "CVE-2014-5030", "CVE-2014-5031" );
	script_name( "Debian Security Advisory DSA 2990-1 (cups - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-27 00:00:00 +0200 (Sun, 27 Jul 2014)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2990.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "cups on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy), these problems have been fixed in
version 1.5.3-5+deb7u4.

For the unstable distribution (sid), these problems have been fixed in
version 1.7.4-2.

We recommend that you upgrade your cups packages." );
	script_tag( name: "summary", value: "It was discovered that the web interface in CUPS, the Common UNIX
Printing System, incorrectly validated permissions on rss files and
directory index files. A local attacker could possibly use this issue
to bypass file permissions and read arbitrary files, possibly leading
to a privilege escalation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cups", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-client", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-common", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cupsddk", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1-dev", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.5.3-5+deb7u4", rls: "DEB7" ) ) != NULL){
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

