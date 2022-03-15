if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891227" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2017-17504", "CVE-2017-17682", "CVE-2017-17879", "CVE-2017-17914" );
	script_name( "Debian LTS: Security Advisory for imagemagick (DLA-1227-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-09 00:00:00 +0100 (Tue, 09 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 00:15:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/01/msg00000.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "imagemagick on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
8:6.7.7.10-5+deb7u19.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities were discovered in ImageMagick, an
image manipulation program, that allow remote attackers to cause a
denial of service (CPU exhaustion via an infinite loop), heap-based
buffer overreads or possibly other unspecified impact via a crafted
image file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-dbg", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++5", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore5", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore5-extra", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand5", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.7.7.10-5+deb7u19", rls: "DEB7" ) )){
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

