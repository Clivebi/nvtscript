if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.67503" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2010-1624" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2010-138-01 pidgin" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(12\\.0|12\\.1|12\\.2|13\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2010-138-01" );
	script_tag( name: "insight", value: "New pidgin packages are available for Slackware 12.0, 12.1, 12.2, 13.0,
and -current to fix a security issue." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2010-138-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "pidgin", ver: "2.7.0-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "pidgin", ver: "2.7.0-i486-1_slack12.1", rls: "SLK12.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "pidgin", ver: "2.7.0-i486-1_slack12.2", rls: "SLK12.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "pidgin", ver: "2.7.0-i486-1_slack13.0", rls: "SLK13.0" ) ) != NULL){
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

