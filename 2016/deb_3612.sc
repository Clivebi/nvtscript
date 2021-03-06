if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703612" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-4994" );
	script_name( "Debian Security Advisory DSA 3612-1 (gimp - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-01 00:00:00 +0200 (Fri, 01 Jul 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3612.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gimp on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this
problem has been fixed in version 2.8.14-1+deb8u1.

We recommend that you upgrade your gimp packages." );
	script_tag( name: "summary", value: "Shmuel H discovered that GIMP, the GNU
Image Manipulation Program, is prone to a use-after-free vulnerability in the channel
and layer properties parsing process when loading a XCF file. An attacker can take
advantage of this flaw to potentially execute arbitrary code with the
privileges of the user running GIMP if a specially crafted XCF file is
processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "gimp", ver: "2.8.14-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gimp-data", ver: "2.8.14-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "gimp-dbg", ver: "2.8.14-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0", ver: "2.8.14-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0-dev", ver: "2.8.14-1+deb8u1", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgimp2.0-doc", ver: "2.8.14-1+deb8u1", rls: "DEB8" ) ) != NULL){
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

