if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71977" );
	script_version( "$Revision: 14202 $" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-10 07:16:19 -0400 (Mon, 10 Sep 2012)" );
	script_name( "Slackware Advisory SSA:2012-195-01 php" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(12\\.0|12\\.1|12\\.2|13\\.0|13\\.1|13\\.37)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2012-195-01" );
	script_tag( name: "insight", value: "New php packages are available for Slackware 12.0, 12.1, 12.2, 13.0, 13.1,
13.37, and -current to fix security issues." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2012-195-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "php", ver: "5.3.14-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "5.3.14-i486-1_slack12.1", rls: "SLK12.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "5.3.14-i486-1_slack12.2", rls: "SLK12.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "5.3.14-i486-1_slack13.0", rls: "SLK13.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "5.3.14-i486-1_slack13.1", rls: "SLK13.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "php", ver: "5.3.14-i486-1_slack13.37", rls: "SLK13.37" ) ) != NULL){
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

