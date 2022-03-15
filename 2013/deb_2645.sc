if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702645" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2010-2529" );
	script_name( "Debian Security Advisory DSA 2645-1 (inetutils - denial of service)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-14 00:00:00 +0100 (Thu, 14 Mar 2013)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2645.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "inetutils on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 2:1.6-3.1+squeeze2.

For the testing distribution (wheezy), this problem has been fixed in
version 2:1.9-2.

For the unstable distribution (sid), this problem has been fixed in
version 2:1.9-2.

We recommend that you upgrade your inetutils packages." );
	script_tag( name: "summary", value: "Ovidiu Mara reported in 2010 a vulnerability in the ping util, commonly used by
system and network administrators. By carefully crafting ICMP responses, an
attacker could make the ping command hangs." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "inetutils-ftp", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-ftpd", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-inetd", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-ping", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-syslogd", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-talk", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-talkd", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-telnet", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-telnetd", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-tools", ver: "2:1.6-3.1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-ftp", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-ftpd", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-inetd", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-ping", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-syslogd", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-talk", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-talkd", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-telnet", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-telnetd", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-tools", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "inetutils-traceroute", ver: "2:1.9-2", rls: "DEB7" ) ) != NULL){
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

