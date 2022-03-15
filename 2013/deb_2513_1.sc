if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702513" );
	script_version( "2020-10-05T06:02:24+0000" );
	script_cve_id( "CVE-2012-1954", "CVE-2012-1967", "CVE-2012-1948" );
	script_name( "Debian Security Advisory DSA 2513-1 (iceape - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2020-10-05 06:02:24 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2513.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "iceape on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-14.

For the unstable (sid) and testing (wheezy) distribution, this problem
will be fixed soon.

We recommend that you upgrade your iceape packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been found in the Iceape internet suite,
an unbranded version of Seamonkey:

CVE-2012-1948Benoit Jacob, Jesse Ruderman, Christian Holler, and Bill McCloskey
identified several memory safety problems that may lead to the execution of
arbitrary code.

CVE-2012-1954Abhishek Arya discovered a use-after-free problem in
nsDocument::AdoptNode that may lead to the execution of arbitrary
code.

CVE-2012-1967moz_bug_r_a4 discovered that in certain cases, javascript: URLs
can be executed so that scripts can escape the JavaScript sandbox and run
with elevated privileges. This can lead to arbitrary code
execution." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "iceape", ver: "2.0.11-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-browser", ver: "2.0.11-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-chatzilla", ver: "2.0.11-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dbg", ver: "2.0.11-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-dev", ver: "2.0.11-14", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "iceape-mailnews", ver: "2.0.11-14", rls: "DEB6" ) ) != NULL){
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

