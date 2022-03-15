if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890547" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2016-5240" );
	script_name( "Debian LTS: Security Advisory for graphicsmagick (DLA-547-2)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-18 01:29:00 +0000 (Fri, 18 May 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00037.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "graphicsmagick on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.3.16-1.1+deb7u6.

We recommend that you upgrade your graphicsmagick packages." );
	script_tag( name: "summary", value: "The fix for CVE-2016-5240 was improperly applied which resulted in GraphicsMagick crashing instead of entering an infinite loop with the given proof of concept.
Furthermore, the original announcement mistakently used the identifier
DLA 574-1 instead of the correct one, DLA 547-1." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-dbg", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-imagemagick-compat", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-libmagick-dev-compat", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphics-magick-perl", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++1-dev", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++3", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick1-dev", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick3", ver: "1.3.16-1.1+deb7u6", rls: "DEB7" ) )){
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

