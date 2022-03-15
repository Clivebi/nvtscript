if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68675" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "2020-12-29 11:25:32 +0000 (Tue, 29 Dec 2020)" );
	script_cve_id( "CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_version( "2020-12-29T11:25:32+0000" );
	script_name( "Slackware Advisory SSA:2010-324-01 xpdf" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(9\\.1|10\\.0|10\\.1|10\\.2|11\\.0|12\\.0|12\\.1|12\\.2|13\\.0|13\\.1)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2010-324-01" );
	script_tag( name: "insight", value: "New xpdf packages are available for Slackware 9.1, 10.0, 10.1, 10.2, 11.0,
12.0, 12.1, 12.2, 13.0, 13.1, and -current to fix security issues." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2010-324-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack9.1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack10.2", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack12.1", rls: "SLK12.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack12.2", rls: "SLK12.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack13.0", rls: "SLK13.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "xpdf", ver: "3.02pl5-i486-1_slack13.1", rls: "SLK13.1" ) ) != NULL){
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

