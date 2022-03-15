if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.57034" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2006-2916" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:C/I:C/A:C" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2006-178-03 arts" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.0|10\\.1|10\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-178-03" );
	script_tag( name: "insight", value: "New aRts packages are available for Slackware 10.0, 10.1, 10.2, and -current
to fix a possible security issue with artswrapper.  The artswrapper program
and the artsd daemon can be used to gain root privileges if artswrapper is
setuid root and the system is running a 2.6.x kernel.  Note that artswrapper
is not setuid root on Slackware by default.  Some people have recommended
setting it that way online though, so it's at least worth warning about.
It's far safer to just add users to the audio group.

The official KDE security advisory is linked in the references." );
	script_xref( name: "URL", value: "http://www.kde.org/info/security/advisory-20060614-2.txt" );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2006-178-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "arts", ver: "1.2.3-i486-2_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "arts", ver: "1.3.2-i486-2_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "arts", ver: "1.4.2-i486-2_slack10.2", rls: "SLK10.2" ) ) != NULL){
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

