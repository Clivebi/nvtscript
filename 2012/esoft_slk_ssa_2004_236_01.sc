if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.53916" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2004-236-01 Qt" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(9\\.0|9\\.1|10\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-236-01" );
	script_tag( name: "insight", value: "New Qt packages are available for Slackware 9.0, 9.1, 10.0, and -current to
fix security issues.  Bugs in the routines that handle PNG, BMP, GIF, and
JPEG images may allow an attacker to cause unauthorized code to execute when
a specially crafted image file is processed.  These flaws may also cause
crashes that lead to a denial of service." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2004-236-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "kde", ver: "3.1.2-i486-4", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "qt", ver: "3.2.1-i486-2", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "qt", ver: "3.3.3-i486-1", rls: "SLK10.0" ) ) != NULL){
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

