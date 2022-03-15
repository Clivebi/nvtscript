if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.63695" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_cve_id( "CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776" );
	script_bugtraq_id( 33598, 33990, 33598, 33990, 31346 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Slackware Advisory SSA:2009-083-03 mozilla-thunderbird" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.2|11\\.0|12\\.0|12\\.1|12\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-083-03" );
	script_tag( name: "insight", value: "New mozilla-thunderbird packages are available for Slackware 10.2, 11.0, 12.0,
12.1, 12.2, and -current to fix security issues." );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/known-vulnerabilities/thunderbird20.html" );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2009-083-03." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "mozilla-thunderbird", ver: "2.0.0.21-i686-1", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-thunderbird", ver: "2.0.0.21-i686-1", rls: "SLK11.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-thunderbird", ver: "2.0.0.21-i686-1", rls: "SLK12.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-thunderbird", ver: "2.0.0.21-i686-1", rls: "SLK12.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-thunderbird", ver: "2.0.0.21-i686-1", rls: "SLK12.2" ) ) != NULL){
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

