if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891681" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2019-7659" );
	script_name( "Debian LTS: Security Advisory for gsoap (DLA-1681-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-19 00:00:00 +0100 (Tue, 19 Feb 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00027.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "gsoap on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in gsoap version
2.8.17-1+deb8u2.

We recommend that you upgrade your gsoap packages. Thanks to Mattias
Ellert <mattias.ellert@physics.uu.se> for their assistance in
preparing this update." );
	script_tag( name: "summary", value: "It was discovered that there was a denial of service vulnerability in
gsoap a C/C++ language binding used for SOAP-based web services." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gsoap", ver: "2.8.17-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gsoap-dbg", ver: "2.8.17-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "gsoap-doc", ver: "2.8.17-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsoap-dbg", ver: "2.8.17-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsoap-dev", ver: "2.8.17-1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgsoap5", ver: "2.8.17-1+deb8u2", rls: "DEB8" ) )){
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

