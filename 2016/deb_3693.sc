if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703693" );
	script_version( "$Revision: 14275 $" );
	script_cve_id( "CVE-2016-6911", "CVE-2016-7568", "CVE-2016-8670" );
	script_name( "Debian Security Advisory DSA 3693-1 (libgd2 - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-10-14 00:00:00 +0200 (Fri, 14 Oct 2016)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3693.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libgd2 on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie), this problem has been fixed in
version 2.1.0-5+deb8u7.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your libgd2 packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in the GD Graphics Library,
which may result in denial of service or potentially the execution of
arbitrary code if a malformed file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgd-dbg", ver: "2.1.0-5+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd-dev", ver: "2.1.0-5+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd-tools", ver: "2.1.0-5+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd2-noxpm-dev", ver: "2.1.0-5+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd2-xpm-dev", ver: "2.1.0-5+deb8u7", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd3", ver: "2.1.0-5+deb8u7", rls: "DEB8" ) ) != NULL){
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

