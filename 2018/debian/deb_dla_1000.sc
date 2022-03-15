if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891000" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2017-9261", "CVE-2017-9262", "CVE-2017-9405", "CVE-2017-9407", "CVE-2017-9409", "CVE-2017-9439", "CVE-2017-9500", "CVE-2017-9501" );
	script_name( "Debian LTS: Security Advisory for imagemagick (DLA-1000-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "imagemagick on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
8:6.7.7.10-5+deb7u15.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "summary", value: "This update fixes several vulnerabilities in imagemagick: Various memory
handling problems and cases of missing or incomplete input sanitising
may result in denial of service if malformed MNG, JNG, ICON, PALM, MPC,
or PDB files are processed." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "imagemagick", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-common", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-dbg", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagick++5", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore5", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickcore5-extra", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libmagickwand5", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "perlmagick", ver: "8:6.7.7.10-5+deb7u15", rls: "DEB7" ) )){
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

