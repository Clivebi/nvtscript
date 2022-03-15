if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.59020" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2007-3387", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2007-316-01 xpdf/poppler/koffice/kdegraphics" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(9\\.1|10\\.0|10\\.1|10\\.2|11\\.0|12\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2007-316-01" );
	script_xref( name: "URL", value: "http://www.kde.org/info/security/advisory-20071107-1.txt" );
	script_tag( name: "insight", value: "New xpdf packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 11.0,
12.0, and -current.  New poppler packages are available for Slackware 12.0
and -current.  New koffice packages are available for Slackware 11.0, 12.0,
and -current.  New kdegraphics packages are available for Slackware 10.2,
11.0, 12.0, and -current.

These updated packages address similar bugs which could be used to crash
applications linked with poppler or that use code from xpdf through the
use of a malformed PDF document.  It is possible that a maliciously
crafted document could cause code to be executed in the context of the
user running the application processing the PDF." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2007-316-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl2-i486-1_slack9.1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl2-i486-1_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl2-i486-1_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kdegraphics", ver: "3.4.2-i486-3_slack10.2", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl2-i486-1_slack10.2", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kdegraphics", ver: "3.5.4-i486-2_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "koffice", ver: "1.5.2-i486-5_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl2-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "kdegraphics", ver: "3.5.7-i486-2_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "poppler", ver: "0.6.2-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "koffice", ver: "1.6.3-i486-2_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl2-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
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

