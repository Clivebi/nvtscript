if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.61605" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2008-3699" );
	script_tag( name: "cvss_base", value: "3.3" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:P/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2008-241-01 amarok" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(11\\.0|12\\.0|12\\.1)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2008-241-01" );
	script_tag( name: "insight", value: "New Amarok packages are available for Slackware 11.0, 12.0, 12.1, and -current
to fix security issues.  In addition, new supporting libgpod packages are
available for Slackware 11.0 and 12.0, since a newer version of libgpod than
shipped with these releases is required to run Amarok version 1.4.10.

The Magnatune music library plugin made insecure use of the /tmp directory,
allowing malicious local users to overwrite files owned by the user running
Amarok through symlink attacks." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2008-241-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "amarok", ver: "1.4.10-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libgpod", ver: "0.6.0-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "amarok", ver: "1.4.10-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libgpod", ver: "0.6.0-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "amarok", ver: "1.4.10-i486-1_slack12.1", rls: "SLK12.1" ) ) != NULL){
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
