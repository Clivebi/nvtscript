if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71862" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-3527", "CVE-2012-3528", "CVE-2012-3529", "CVE-2012-3530", "CVE-2012-3531" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-07 11:46:25 -0400 (Fri, 07 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2537-1 (typo3-src)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202537-1" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in TYPO3, a content management
system.

CVE-2012-3527
An insecure call to unserialize in the help system enables
arbitrary code execution by authenticated users.

CVE-2012-3528
The TYPO3 backend contains several cross-site scripting
vulnerabilities.

CVE-2012-3529
Authenticated users who can access the configuration module
can obtain the encryption key, allowing them to escalate their
privileges.

CVE-2012-3530
The RemoveXSS HTML sanitizer did not remove several HTML5
JavaScript, thus failing to mitigate the impact of cross-site
scripting vulnerabilities.

For the stable distribution (squeeze), these problems have been fixed
in version 4.3.9+dfsg1-1+squeeze5.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 4.5.19+dfsg1-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your typo3-src packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to typo3-src
announced via advisory DSA 2537-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "typo3", ver: "4.3.9+dfsg1-1+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-database", ver: "4.3.9+dfsg1-1+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-src-4.3", ver: "4.3.9+dfsg1-1+squeeze5", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3", ver: "4.5.19+dfsg1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-database", ver: "4.5.19+dfsg1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-dummy", ver: "4.5.19+dfsg1-1", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "typo3-src-4.5", ver: "4.5.19+dfsg1-1", rls: "DEB7" ) ) != NULL){
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

