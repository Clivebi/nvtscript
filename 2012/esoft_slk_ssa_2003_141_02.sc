if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.53895" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2003-141-02 BitchX security fixes" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(8\\.1|9\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2003-141-02" );
	script_tag( name: "insight", value: "New BitchX packages are available to fix security problems found
by Timo Sirainen.  BitchX is an IRC (Internet Relay Chat) client.
Under certain circumstances, a malicious IRC server could cause
BitchX to crash, or possibly to run arbitrary code as the user
running BitchX." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2003-141-02." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "bitchx", ver: "1.0c19-i386-3", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bitchx", ver: "1.0c19-i386-3", rls: "SLK9.0" ) ) != NULL){
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

