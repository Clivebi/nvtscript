if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70541" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3148", "CVE-2011-3149" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-02-11 02:26:19 -0500 (Sat, 11 Feb 2012)" );
	script_name( "Debian Security Advisory DSA 2326-1 (pam)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202326-1" );
	script_tag( name: "insight", value: "Kees Cook of the ChromeOS security team discovered a buffer overflow
in pam_env, a PAM module to set environment variables through the
PAM stack, which allowed the execution of arbitrary code. An additional
issue in argument parsing allows denial of service.

The oldstable distribution (lenny) is not affected.

For the stable distribution (squeeze), this problem has been fixed in
version 1.1.1-6.1+squeeze1.

For the unstable distribution (sid), this problem will be fixed soon
(the impact in sid is limited to denial of service for both issues)" );
	script_tag( name: "solution", value: "We recommend that you upgrade your pam packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to pam
announced via advisory DSA 2326-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libpam-cracklib", ver: "1.1.1-6.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-doc", ver: "1.1.1-6.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-modules", ver: "1.1.1-6.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam-runtime", ver: "1.1.1-6.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam0g", ver: "1.1.1-6.1+squeeze1", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libpam0g-dev", ver: "1.1.1-6.1+squeeze1", rls: "DEB6" ) ) != NULL){
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

