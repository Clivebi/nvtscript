if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.63229" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_version( "$Revision: 14202 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Slackware Advisory SSA:2009-015-01 bind 10.2/11.0 recompile" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.2|11\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-015-01" );
	script_tag( name: "insight", value: "Updated bind packages are available for Slackware 10.2 and 11.0 to address a
load problem.  It was reported that the initial build of these updates
complained that the Linux capability module was not present and would refuse
to load.  It was determined that the packages which were compiled on 10.2
and 11.0 systems running 2.6 kernels, and although the installed kernel
headers are from 2.4.x, it picked up on this resulting in packages that
would only run under 2.4 kernels.  These new packages address the issue.

As always, any problems noted with update patches should be reported to
security@slackware.com, and we will do our best to address them as quickly as
possible." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2009-015-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.3.6_P1-i486-2_slack10.2", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.3.6_P1-i486-2_slack11.0", rls: "SLK11.0" ) ) != NULL){
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

