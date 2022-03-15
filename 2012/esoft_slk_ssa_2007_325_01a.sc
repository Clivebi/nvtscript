if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.59023" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2007-5266", "CVE-2007-5267", "CVE-2007-5268", "CVE-2007-5269" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2007-325-01a libpng for Slackware 10.1 and 10.2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.1|10\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2007-325-01a" );
	script_tag( name: "insight", value: "New libpng packages are available for Slackware 10.1 and 10.2 that
were left out of the last batch of updates.  These fix the same
security problems as the other 1.2.23 upgrades." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2007-325-01a." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.23-i486-1_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "libpng", ver: "1.2.23-i486-1_slack10.2", rls: "SLK10.2" ) ) != NULL){
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
