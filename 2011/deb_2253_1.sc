if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69960" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2010-4259" );
	script_name( "Debian Security Advisory DSA 2253-1 (fontforge)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202253-1" );
	script_tag( name: "insight", value: "Ulrik Persson reported a stack-based buffer overflow flaw in FontForge,
a font editor. When processed a crafted Bitmap Distribution Format (BDF)
FontForge could crash or execute arbitrary code with the privileges of
the user running FontForge.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.0.20080429-1+lenny2.

For the stable distribution (squeeze), testing distribution (wheezy),
and unstable distribution (sid) are not affected by this problem." );
	script_tag( name: "solution", value: "We recommend that you upgrade your fontforge packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to fontforge
announced via advisory DSA 2253-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "fontforge", ver: "0.0.20080429-1+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "fontforge-doc", ver: "0.0.20080429-1+lenny2", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-fontforge", ver: "0.0.20080429-1+lenny2", rls: "DEB5" ) ) != NULL){
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

