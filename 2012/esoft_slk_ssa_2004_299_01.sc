if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.53903" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2004-0492", "CVE-2004-0885" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2004-299-01 apache, mod_ssl, php " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(8\\.1|9\\.0|9\\.1|10\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-299-01" );
	script_tag( name: "insight", value: "New apache and mod_ssl packages are available for Slackware 8.1, 9.0, 9.1,
10.0, and -current to fix security issues.  Apache has been upgraded to
version 1.3.32 which fixes a heap-based buffer overflow in mod_proxy.
mod_ssl was upgraded from version mod_ssl-2.8.19-1.3.31 to version
2.8.21-1.3.32 which corrects a flaw allowing a client to use a cipher
which the server does not consider secure enough.

A new PHP package (php-4.3.9) is also available for all of these platforms." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2004-299-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.32-i386-1", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mod_ssl", ver: "2.8.21_1.3.32-i386-1", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "4.3.9-i386-1", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.32-i386-1", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mod_ssl", ver: "2.8.21_1.3.32-i386-1", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "4.3.9-i386-1", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.32-i486-1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mod_ssl", ver: "2.8.21_1.3.32-i486-1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "4.3.9-i486-1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.32-i486-1", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mod_ssl", ver: "2.8.21_1.3.32-i486-1", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "4.3.9-i486-1", rls: "SLK10.0" ) ) != NULL){
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

