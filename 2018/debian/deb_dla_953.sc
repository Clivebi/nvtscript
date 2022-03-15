if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890953" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2017-9098" );
	script_name( "Debian LTS: Security Advisory for graphicsmagick (DLA-953-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-28 16:32:00 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/05/msg00024.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "graphicsmagick on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.3.16-1.1+deb7u7.

We recommend that you upgrade your graphicsmagick packages." );
	script_tag( name: "summary", value: "Chris Evans discovered that graphicsmagick used uninitialized memory
in the RLE decoder, allowing a remote attacker to leak sensitive
information from process memory space." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-dbg", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-imagemagick-compat", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "graphicsmagick-libmagick-dev-compat", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphics-magick-perl", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++1-dev", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick++3", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick1-dev", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgraphicsmagick3", ver: "1.3.16-1.1+deb7u7", rls: "DEB7" ) )){
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

