if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.57701" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "2019-10-07 14:34:48 +0000 (Mon, 07 Oct 2019)" );
	script_cve_id( "CVE-2006-6235", "CVE-2006-6169" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "2019-10-07T14:34:48+0000" );
	script_name( "Slackware Advisory SSA:2006-340-01 gnupg" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(9\\.0|9\\.1|10\\.0|10\\.1|10\\.2|11\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-340-01" );
	script_tag( name: "insight", value: "New gnupg packages are available for Slackware 9.0, 9.1, 10.0, 10.1,
  10.2, and 11.0 to fix security issues.

  More details about the issues are linked in the references." );
	script_xref( name: "URL", value: "http://lists.gnupg.org/pipermail/gnupg-announce/2006q4/000491.html" );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
  via advisory SSA:2006-340-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "gnupg", ver: "1.4.6-i386-1_slack9.0", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "gnupg", ver: "1.4.6-i486-1_slack9.1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "gnupg", ver: "1.4.6-i486-1_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "gnupg", ver: "1.4.6-i486-1_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "gnupg", ver: "1.4.6-i486-1_slack10.2", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "gnupg", ver: "1.4.6-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
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
