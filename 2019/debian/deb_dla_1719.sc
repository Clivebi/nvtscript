if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891719" );
	script_version( "2021-09-03T14:02:28+0000" );
	script_cve_id( "CVE-2018-14498" );
	script_name( "Debian LTS: Security Advisory for libjpeg-turbo (DLA-1719-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 14:02:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-19 00:00:00 +0100 (Tue, 19 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 21:15:00 +0000 (Fri, 31 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00021.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libjpeg-turbo on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in libjpeg-turbo
version 1:1.3.1-12+deb8u2.

We recommend that you upgrade your libjpeg-turbo packages." );
	script_tag( name: "summary", value: "It was discovered that there was a denial of service vulnerability in
the libjpeg-turbo CPU-optimised JPEG image library. A heap-based
buffer over-read could be triggered by a specially-crafted bitmap
(BMP) file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjpeg-dev", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg-turbo-progs", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg-turbo-progs-dbg", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg62-turbo", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg62-turbo-dbg", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg62-turbo-dev", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libturbojpeg1", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libturbojpeg1-dbg", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libturbojpeg1-dev", ver: "1:1.3.1-12+deb8u2", rls: "DEB8" ) )){
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

