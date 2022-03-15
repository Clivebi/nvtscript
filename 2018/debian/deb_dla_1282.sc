if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891282" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2018-6799" );
	script_name( "Debian LTS: Security Advisory for graphicsmagick (DLA-1282-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-30 03:15:00 +0000 (Sun, 30 Jun 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/02/msg00017.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "graphicsmagick on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.3.16-1.1+deb7u18.

We recommend that you upgrade your graphicsmagick packages." );
	script_tag( name: "summary", value: "A denial of service vulnerability has been discovered in graphicsmagick,
a collection of image processing tools and associated libraries.

A specially crafted file can be used to produce a denial of service
(heap overwrite) or possible other unspecified impact by exploiting a
defect related to unused pixel staging area in the AcquireCacheNexus
function in magick/pixel_cache.c." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-dbg", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-imagemagick-compat", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-libmagick-dev-compat", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphics-magick-perl", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++1-dev", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++3", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick1-dev", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick3", ver: "1.3.16-1.1+deb7u18", rls: "DEB7" ) )){
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

