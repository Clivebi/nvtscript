if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.58163" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2007-085-01 mozilla-firefox" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(10\\.2|11\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2007-085-01" );
	script_tag( name: "insight", value: "New mozilla-firefox packages are available for Slackware 10.2, 11.0,
and -current to fix security issues.

Note that firefox-1.5.x will reach end-of-life next month, so upgrading
to the 2.x branch soon is probably a good idea.

'Note: Firefox 1.5.0.x will be maintained with security and stability
updates until April 24, 2007. All users are encouraged to upgrade
to Firefox 2.'

Since Slackware packages the official Firefox binaries, the Firefox 2
packages in Slackware 11.0 and -current should run on many earlier
Slackware versions as well, though there are some known problems with
plugins (such as gxine)." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2007-085-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "mozilla-firefox", ver: "1.5.0.11-i686-1", rls: "SLK10.2" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "mozilla-firefox", ver: "2.0.0.3-i686-1", rls: "SLK11.0" ) ) != NULL){
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

