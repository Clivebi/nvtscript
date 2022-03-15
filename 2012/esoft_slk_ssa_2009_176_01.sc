if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.64317" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2009-1307", "CVE-2009-1311", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841", "CVE-2009-2210" );
	script_bugtraq_id( 34656, 35370, 35326, 35371, 35391, 35380, 35461 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Slackware Advisory SSA:2009-176-01 seamonkey" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(11\\.0|12\\.0|12\\.1|12\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-176-01" );
	script_tag( name: "insight", value: "New seamonkey packages are available for Slackware 11.0, 12.0, 12.1, 12.2,
and -current to fix security issues." );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/known-vulnerabilities/seamonkey11.html" );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2009-176-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "seamonkey", ver: "1.1.17-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "seamonkey", ver: "1.1.17-i486-1_slack12.0", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "seamonkey", ver: "1.1.17-i486-1_slack12.1", rls: "SLK12.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "seamonkey", ver: "1.1.17-i486-1_slack12.2", rls: "SLK12.2" ) ) != NULL){
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

