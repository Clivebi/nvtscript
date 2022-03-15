if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703369" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-5723" );
	script_name( "Debian Security Advisory DSA 3369-1 (zendframework - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-10-06 00:00:00 +0200 (Tue, 06 Oct 2015)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3369.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(7|9|8)" );
	script_tag( name: "affected", value: "zendframework on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (wheezy), this problem has been fixed
in version 1.11.13-1.1+deb7u4.

For the stable distribution (jessie), this problem has been fixed in
version 1.12.9+dfsg-2+deb8u4.

For the testing distribution (stretch), this problem has been fixed
in version 1.12.16+dfsg-1.

For the unstable distribution (sid), this problem has been fixed in
version 1.12.16+dfsg-1.

We recommend that you upgrade your zendframework packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities were discovered in Zend Framework, a PHP
framework:

CVE-2015-5723
It was discovered that due to incorrect permissions masks when
creating directories, local attackers could potentially execute
arbitrary code or escalate privileges.

ZF2015-08 (no CVE assigned)

Chris Kings-Lynne discovered an SQL injection vector caused by
missing null byte filtering in the MS SQL PDO backend, and a similar
issue was also found in the SQLite backend." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "zendframework", ver: "1.11.13-1.1+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework-bin", ver: "1.11.13-1.1+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework-resources", ver: "1.11.13-1.1+deb7u4", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework", ver: "1.12.16+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework-bin", ver: "1.12.16+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework-resources", ver: "1.12.16+dfsg-1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework", ver: "1.12.9+dfsg-2+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework-bin", ver: "1.12.9+dfsg-2+deb8u4", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zendframework-resources", ver: "1.12.9+dfsg-2+deb8u4", rls: "DEB8" ) ) != NULL){
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

