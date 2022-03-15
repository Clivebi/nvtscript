if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.54459" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2005-0468", "CVE-2005-0469" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2005-210-01 telnet client" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(8\\.1|9\\.0|9\\.1|10\\.0|10\\.1)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2005-210-01" );
	script_tag( name: "insight", value: "New tcpip packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
and -current to fix a security issues with the telnet client.  Overflows in
the telnet client may lead to the execution of arbitrary code as the telnet
user if the user connects to a malicious telnet server." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2005-210-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "tcpip", ver: "0.17-i386-13b", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "tcpip", ver: "0.17-i386-16b", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "tcpip", ver: "0.17-i486-24b", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "tcpip", ver: "0.17-i486-29b", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "tcpip", ver: "0.17-i486-31b", rls: "SLK10.1" ) ) != NULL){
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
