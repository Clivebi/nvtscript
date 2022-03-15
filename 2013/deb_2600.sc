if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702600" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-5519" );
	script_name( "Debian Security Advisory DSA 2600-1 (cups - privilege escalation)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-01-06 00:00:00 +0100 (Sun, 06 Jan 2013)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2013/dsa-2600.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "cups on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 1.4.4-7+squeeze2.

For the testing distribution (wheezy), this problem has been fixed in
version 1.5.3-2.7.

For the unstable distribution (sid), this problem has been fixed in
version 1.5.3-2.7.

We recommend that you upgrade your cups packages." );
	script_tag( name: "summary", value: "Jann Horn discovered that users of the CUPS printing system who are part
of the lpadmin group could modify several configuration parameters with
security impact. Specifically, this allows an attacker to read or write
arbitrary files as root which can be used to elevate privileges.

This update splits the configuration file /etc/cups/cupsd.conf into two
files: cupsd.conf and cups-files.conf. While the first stays configurable
via the web interface, the latter can only be configured by the root user.
Please see the updated documentation that comes with the new package
for more information on these files." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "cups", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-client", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-common", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cupsddk", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1-dev", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.4.4-7+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-client", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-common", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "cupsddk", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsdriver1-dev", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.5.3-2.7", rls: "DEB7" ) ) != NULL){
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

