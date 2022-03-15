if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702462" );
	script_version( "2021-07-02T02:00:36+0000" );
	script_cve_id( "CVE-2012-1798", "CVE-2012-1185", "CVE-2012-1610", "CVE-2012-1186", "CVE-2012-0260", "CVE-2012-0259" );
	script_name( "Debian Security Advisory DSA 2462-2 (imagemagick - several vulnerabilities)" );
	script_tag( name: "last_modification", value: "2021-07-02 02:00:36 +0000 (Fri, 02 Jul 2021)" );
	script_tag( name: "creation_date", value: "2013-09-18 11:53:02 +0200 (Wed, 18 Sep 2013)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 18:39:00 +0000 (Fri, 31 Jul 2020)" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2012/dsa-2462.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_tag( name: "affected", value: "imagemagick on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (squeeze), this problem has been fixed in
version 6.6.0.4-3+squeeze3.

For the unstable distribution (sid), this problem has been fixed in
version 8:6.7.4.0-5.

We recommend that you upgrade your imagemagick packages." );
	script_tag( name: "summary", value: "Several integer overflows and missing input validations were discovered
in the ImageMagick image manipulation suite, resulting in the execution
of arbitrary code or denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "imagemagick", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-dbg", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "imagemagick-doc", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++-dev", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagick++3", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore-dev", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore3", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickcore3-extra", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand-dev", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libmagickwand3", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "perlmagick", ver: "6.6.0.4-3+squeeze3", rls: "DEB6" ) ) != NULL){
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

