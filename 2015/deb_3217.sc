if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703217" );
	script_version( "$Revision: 14278 $" );
	script_cve_id( "CVE-2015-0840" );
	script_name( "Debian Security Advisory DSA 3217-1 (dpkg - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-09 00:00:00 +0200 (Thu, 09 Apr 2015)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2015/dsa-3217.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "dpkg on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (wheezy),
this problem has been fixed in version 1.16.16. This update also includes
non-security changes previously scheduled for the next wheezy point release.
See the Debian changelog for details.

For the unstable distribution (sid), this problem has been fixed in
version 1.17.25.

We recommend that you upgrade your dpkg packages." );
	script_tag( name: "summary", value: "Jann Horn discovered that the source
package integrity verification in dpkg-source can be bypassed via a specially
crafted Debian source control file (.dsc). Note that this flaw only affects
extraction of local Debian source packages via dpkg-source but not the installation
of packages from the Debian archive." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "dpkg", ver: "1.16.16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dpkg-dev", ver: "1.16.16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "dselect", ver: "1.16.16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdpkg-dev", ver: "1.16.16", rls: "DEB7" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libdpkg-perl", ver: "1.16.16", rls: "DEB7" ) ) != NULL){
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

