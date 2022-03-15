if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69738" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-4802", "CVE-2010-4803", "CVE-2011-1841" );
	script_name( "Debian Security Advisory DSA 2239-1 (libmojolicious-perl)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202239-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered Mojolicious, a Perl Web
Application Framework. The link_to helper was affected by cross-site
scripting and implementation errors in the MD5 HMAC and CGI environment
handling have been corrected.

The oldstable distribution (lenny) doesn't include libmojolicious-perl.

For the stable distribution (squeeze), this problem has been fixed in
version 0.999926-1+squeeze2.

For the unstable distribution (sid), this problem has been fixed in
version 1.12-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your libmojolicious-perl packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to libmojolicious-perl
announced via advisory DSA 2239-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmojolicious-perl", ver: "0.999926-1+squeeze2", rls: "DEB6" ) ) != NULL){
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

