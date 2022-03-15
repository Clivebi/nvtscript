if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891055" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2017-7890" );
	script_name( "Debian LTS: Security Advisory for libgd2 (DLA-1055-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-04 01:29:00 +0000 (Fri, 04 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/08/msg00007.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libgd2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
2.0.36~rc1~dfsg-6.1+deb7u9.

We recommend that you upgrade your libgd2 packages." );
	script_tag( name: "summary", value: "Matviy Kotoniy reported that the gdImageCreateFromGifCtx() function used
to load images from GIF format files in libgd2, a library for
programmatic graphics creation and manipulation, does not zero stack
allocated color map buffers before their use, which may result in
information disclosure if a specially crafted file is processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libgd-tools", ver: "2.0.36~rc1~dfsg-6.1+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-noxpm", ver: "2.0.36~rc1~dfsg-6.1+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-noxpm-dev", ver: "2.0.36~rc1~dfsg-6.1+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-xpm", ver: "2.0.36~rc1~dfsg-6.1+deb7u9", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgd2-xpm-dev", ver: "2.0.36~rc1~dfsg-6.1+deb7u9", rls: "DEB7" ) )){
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

