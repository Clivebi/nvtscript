if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891551" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-10958", "CVE-2018-10999", "CVE-2018-16336" );
	script_name( "Debian LTS: Security Advisory for exiv2 (DLA-1551-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-10-22 00:00:00 +0200 (Mon, 22 Oct 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/10/msg00012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "exiv2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.24-4.1+deb8u2.

We recommend that you upgrade your exiv2 packages." );
	script_tag( name: "summary", value: "A vulnerability has been discovered in exiv2 (CVE-2018-16336), a C++
library and a command line utility to manage image metadata, resulting
in remote denial of service (heap-based buffer over-read/overflow) via
a crafted image file.

Additionally, this update includes a minor change to the patch for the
CVE-2018-10958/CVE-2018-10999 vulnerability first addressed in DLA
1402-1. The initial patch was overly restrictive and has been adjusted
to remove the excessive restriction." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "exiv2", ver: "0.24-4.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-13", ver: "0.24-4.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dbg", ver: "0.24-4.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-dev", ver: "0.24-4.1+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libexiv2-doc", ver: "0.24-4.1+deb8u2", rls: "DEB8" ) )){
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

