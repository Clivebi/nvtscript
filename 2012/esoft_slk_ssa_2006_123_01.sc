if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.56691" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_bugtraq_id( 17795 );
	script_cve_id( "CVE-2006-1526" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2006-123-01 xorg server overflow" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.1|10\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-123-01" );
	script_xref( name: "URL", value: "http://lists.freedesktop.org/archives/xorg/2006-May/015136.html" );
	script_tag( name: "insight", value: "New xorg and xorg-devel packages are available for Slackware 10.1, 10.2,
and -current to fix a security issue.  A typo in the X render extension
in X.Org 6.8.0 or later allows an X client to crash the server and
possibly to execute arbitrary code as the X server user (typically this
is 'root'.)" );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2006-123-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "x11", ver: "6.8.1-i486-5", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "x11-devel", ver: "6.8.1-i486-5", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "x11", ver: "6.8.2-i486-5", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "x11-devel", ver: "6.8.2-i486-5", rls: "SLK10.2" ) ) != NULL){
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

