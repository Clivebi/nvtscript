if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71490" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1954", "CVE-2012-1966", "CVE-2012-1967" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-10 03:12:19 -0400 (Fri, 10 Aug 2012)" );
	script_name( "Debian Security Advisory DSA 2514-1 (iceweasel)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202514-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in Iceweasel, a web
browser based on Firefox. The included XULRunner library provides
rendering services for several other applications included in Debian.

CVE-2012-1948

Benoit Jacob, Jesse Ruderman, Christian Holler, and Bill McCloskey
identified several memory safety problems that may lead to the
execution of arbitrary code.

CVE-2012-1950

Mario Gomes and Code Audit Labs discovered that it is possible
to force iceweasel to display the URL of the previous entered site
through drag and drop actions to the address bar. This can be
abused to perform phishing attacks.

CVE-2012-1954

Abhishek Arya discovered a use-after-free problem in nsDocument::AdoptNode
that may lead to the execution of arbitrary code.

CVE-2012-1966

moz_bug_r_a4 discovered that it is possible to perform cross-site
scripting attacks through the context menu when using data: URLs.

CVE-2012-1967

moz_bug_r_a4 discovered that in certain cases, javascript: URLs can
be executed so that scripts can escape the JavaScript sandbox and run
with elevated privileges.

Note: We'd like to advise users of Iceweasel's 3.5 branch in Debian
stable to consider to upgrade to the Iceweasel 10.0 ESR (Extended
Support Release) which is now available in Debian Backports.
Although Debian will continue to support Iceweasel 3.5 in stable with
security updates, this can only be done on a best effort base as
upstream provides no such support anymore. On top of that, the 10.0
branch adds proactive security features to the browser.


For the stable distribution (squeeze), this problem has been fixed in
version 3.5.16-17.

For the unstable distribution (sid), this problem has been fixed in
version 10.0.6esr-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your iceweasel packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to iceweasel
announced via advisory DSA 2514-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceweasel", ver: "3.5.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceweasel-dbg", ver: "3.5.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs-dev", ver: "1.9.1.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs2d", ver: "1.9.1.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmozjs2d-dbg", ver: "1.9.1.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "spidermonkey-bin", ver: "1.9.1.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9.1", ver: "1.9.1.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-1.9.1-dbg", ver: "1.9.1.16-17", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "xulrunner-dev", ver: "1.9.1.16-17", rls: "DEB6" ) ) != NULL){
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

