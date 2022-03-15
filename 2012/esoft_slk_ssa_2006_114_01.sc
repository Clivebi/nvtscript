if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.56693" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2006-114-01 mozilla security/EOL" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.0|10\\.1|10\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-114-01" );
	script_xref( name: "URL", value: "http://www.mozilla.org/projects/security/known-vulnerabilities.html#mozilla" );
	script_tag( name: "insight", value: "New Mozilla packages are available for Slackware 10.0, 10.1,
10.2 and -current to fix multiple security issues.

Also note that this release marks the EOL (End Of Life) for the Mozilla
Suite series.  It's been a great run, so thanks to everyone who put in
so much effort to make Mozilla a great browser suite.  In the next
Slackware release fans of the Mozilla Suite will be able to look
forward to browsing with SeaMonkey, the Suite's successor.  Anyone
using an older version of Slackware may want to start thinking about
migrating to another browser -- if not now, when the next problems
with Mozilla are found.

Although the 'sunset announcement' states that mozilla-1.7.13 is the
final mozilla release, I wouldn't be too surprised to see just one
more since there's a Makefile.in bug that needed to be patched here
before Mozilla 1.7.13 would build.  If a new release comes out and
fixes only that issue, don't look for a package release on that as
it's already fixed in these packages.  If additional issues are
fixed, then there will be new packages.  Basically, if upstream
un-EOLs this for a good reason, so will we." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2006-114-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "mozilla", ver: "1.7.13-i486-1", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-plugins", ver: "1.7.13-noarch-1", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla", ver: "1.7.13-i486-1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-plugins", ver: "1.7.13-noarch-1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla", ver: "1.7.13-i486-1", rls: "SLK10.2" ) ) != NULL){
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

