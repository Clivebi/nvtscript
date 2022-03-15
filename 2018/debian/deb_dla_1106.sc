if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891106" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-6362" );
	script_name( "Debian LTS: Security Advisory for libgd2 (DLA-1106-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-13 17:46:00 +0000 (Wed, 13 Sep 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00022.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libgd2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.0.36~rc1~dfsg-6.1+deb7u10.

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
if(!isnull( res = isdpkgvuln( pkg: "libgd-tools", ver: "2.0.36~rc1~dfsg-6.1+deb7u10", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-noxpm", ver: "2.0.36~rc1~dfsg-6.1+deb7u10", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-noxpm-dev", ver: "2.0.36~rc1~dfsg-6.1+deb7u10", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-xpm", ver: "2.0.36~rc1~dfsg-6.1+deb7u10", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-xpm-dev", ver: "2.0.36~rc1~dfsg-6.1+deb7u10", rls: "DEB7" ) )){
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

