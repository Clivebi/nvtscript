if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68663" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-3776", "CVE-2010-3778", "CVE-2010-3769", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3775", "CVE-2010-3767", "CVE-2010-3773", "CVE-2010-3770" );
	script_name( "Debian Security Advisory DSA 2132-1 (xulrunner)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202132-1" );
	script_tag( name: "insight", value: "Several remote vulnerabilities have been discovered in Xulrunner, a
runtime environment for XUL applications. The Common Vulnerabilities
and Exposures project identifies the following problems:

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-7.

For the upcoming stable version (squeeze) and the unstable
distribution (sid), these problems have been fixed in version 3.5.15-1.

For the experimental distribution, these problems have been fixed in
version 3.6.13-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your xulrunner packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to xulrunner
announced via advisory DSA 2132-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libmozillainterfaces-java", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs-dev", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9-dbg", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs1d", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "python-xpcom", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spidermonkey-bin", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs1d-dbg", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9-gnome-support", ver: "1.9.0.19-7", rls: "DEB5" ) ) != NULL){
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

