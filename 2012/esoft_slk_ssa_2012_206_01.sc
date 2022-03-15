if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71970" );
	script_cve_id( "CVE-2011-3045", "CVE-2011-3048", "CVE-2012-3386" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14202 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-10 07:16:18 -0400 (Mon, 10 Sep 2012)" );
	script_name( "Slackware Advisory SSA:2012-206-01 libpng" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(8\\.1|9\\.0|9\\.1|10\\.0|10\\.1|10\\.2|11\\.0|12\\.0|12\\.1|12\\.2|13\\.0|13\\.1|13\\.37)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2012-206-01" );
	script_tag( name: "insight", value: "New libpng packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, 11.0, 12.0, 12.1, 12.2, 13.0, 13.1, 13.37, and -current to fix
security issues." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2012-206-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i386-1_slack8.1", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i386-1_slack9.0", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack9.1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack10.2", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack12.1", rls: "SLK12.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack12.2", rls: "SLK12.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.50-i486-1_slack13.0", rls: "SLK13.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.4.12-i486-1_slack13.1", rls: "SLK13.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.4.12-i486-1_slack13.37", rls: "SLK13.37" ) ) != NULL){
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

