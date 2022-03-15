if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703961" );
	script_version( "2021-09-15T10:01:53+0000" );
	script_cve_id( "CVE-2017-6362" );
	script_name( "Debian Security Advisory DSA 3961-1 (libgd2 - security update)" );
	script_tag( name: "last_modification", value: "2021-09-15 10:01:53 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-03 00:00:00 +0200 (Sun, 03 Sep 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-13 17:46:00 +0000 (Wed, 13 Sep 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-3961.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libgd2 on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), this problem has been fixed
in version 2.1.0-5+deb8u11.

For the stable distribution (stretch), this problem has been fixed in
version 2.2.4-2+deb9u2.

For the unstable distribution (sid), this problem has been fixed in
version 2.2.5-1.

We recommend that you upgrade your libgd2 packages." );
	script_tag( name: "summary", value: "A double-free vulnerability was discovered in the gdImagePngPtr()
function in libgd2, a library for programmatic graphics creation and
manipulation, which may result in denial of service or potentially the
execution of arbitrary code if a specially crafted file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libgd-dev", ver: "2.2.4-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd-tools", ver: "2.2.4-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd3", ver: "2.2.4-2+deb9u2", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd-dbg", ver: "2.1.0-5+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd-dev", ver: "2.1.0-5+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd-tools", ver: "2.1.0-5+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd2-noxpm-dev", ver: "2.1.0-5+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd2-xpm-dev", ver: "2.1.0-5+deb8u11", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libgd3", ver: "2.1.0-5+deb8u11", rls: "DEB8" ) ) != NULL){
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

