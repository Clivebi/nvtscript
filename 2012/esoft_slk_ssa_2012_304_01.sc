if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72571" );
	script_version( "$Revision: 14202 $" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-11-16 03:15:58 -0500 (Fri, 16 Nov 2012)" );
	script_name( "Slackware Advisory SSA:2012-304-01 mozilla-thunderbird" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(13\\.37|14\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2012-304-01" );
	script_tag( name: "insight", value: "New mozilla-thunderbird packages are available for Slackware 13.37, 14.0,
and -current to fix security issues." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2012-304-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "mozilla-thunderbird", ver: "16.0.2-i486-1_slack13.37", rls: "SLK13.37" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-thunderbird", ver: "16.0.2-i486-1_slack14.0", rls: "SLK14.0" ) ) != NULL){
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

