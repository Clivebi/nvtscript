if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.57698" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_cve_id( "CVE-2006-4339" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2006-310-01 bind" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(8\\.1|9\\.0|9\\.1|10\\.0|10\\.1|10\\.2|11\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-310-01" );
	script_tag( name: "insight", value: "New bind packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1, 10.2,
and 11.0 to fix security issues.  The minimum OpenSSL version was raised to
OpenSSL 0.9.7l and OpenSSL 0.9.8d to avoid exposure to known security flaws
in older versions (these patches were already issued for Slackware).  If you
have not upgraded yet, get those as well to prevent a potentially exploitable
security problem in named.

In addition, the default RSA exponent was changed from 3 to 65537.

Both of these issues are essentially the same as ones discovered in OpenSSL at
the end of September 2006, only now there's protection against compiling using
the wrong OpenSSL version.  RSA keys using exponent 3 (which was previously
BIND's default) will need to be regenerated to protect against the forging of
RRSIGs." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2006-310-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.2.6_P2-i386-1_slack8.1", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.2.6_P2-i386-1_slack9.0", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.2.6_P2-i486-1_slack9.1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.2.6_P2-i486-1_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.3.2_P2-i486-1_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.3.2_P2-i486-1_slack10.2", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "bind", ver: "9.3.2_P2-i486-1_slack11.0", rls: "SLK11.0" ) ) != NULL){
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

