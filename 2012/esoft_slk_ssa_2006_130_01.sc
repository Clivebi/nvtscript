if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.56729" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2006-130-01 Apache httpd redux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(8\\.1|9\\.0|9\\.1|10\\.0|10\\.1|10\\.2)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2006-130-01" );
	script_tag( name: "insight", value: "New Apache packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1,
10.2, and -current to fix a bug with Apache 1.3.35 and glibc that
breaks wildcards in Include directives.  It may not occur with all
versions of glibc, but it has been verified on -current (using an Include
within a file already Included causes a crash), so better to patch it
and reissue these packages just to be sure.  My apologies if the last
batch of updates caused anyone undue grief...  they worked here with my
(too simple?) config files.

Note that if you use mod_ssl, you'll also require the mod_ssl package
that was part of yesterday's release, and on -current you'll need the
newest PHP package (if you use PHP).

Thanks to Francesco Gringoli for bringing this issue to my attention." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2006-130-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.35-i386-2_slack8.1", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.35-i386-2_slack9.0", rls: "SLK9.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.35-i486-2_slack9.1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.35-i486-2_slack10.0", rls: "SLK10.0" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.35-i486-2_slack10.1", rls: "SLK10.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "apache", ver: "1.3.35-i486-2_slack10.2", rls: "SLK10.2" ) ) != NULL){
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

