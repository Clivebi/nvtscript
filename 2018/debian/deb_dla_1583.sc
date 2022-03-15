if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891583" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2015-5203", "CVE-2015-5221", "CVE-2016-8690", "CVE-2016-8884", "CVE-2016-8885", "CVE-2017-13748", "CVE-2017-14132" );
	script_name( "Debian LTS: Security Advisory for jasper (DLA-1583-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-11-21 00:00:00 +0100 (Wed, 21 Nov 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-05 14:53:00 +0000 (Fri, 05 Feb 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/11/msg00023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "jasper on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.900.1-debian1-2.4+deb8u4.

We recommend that you upgrade your jasper packages." );
	script_tag( name: "summary", value: "Several security vulnerabilities were discovered in the JasPer
JPEG-2000 library.

CVE-2015-5203

Gustavo Grieco discovered an integer overflow vulnerability that
allows remote attackers to cause a denial of service or may have
other unspecified impact via a crafted JPEG 2000 image file.

CVE-2015-5221

Josselin Feist found a double-free vulnerability that allows remote
attackers to cause a denial-of-service (application crash) by
processing a malformed image file.

CVE-2016-8690

Gustavo Grieco discovered a NULL pointer dereference vulnerability
that can cause a denial-of-service via a crafted BMP image file. The
update also includes the fixes for the related issues CVE-2016-8884
and CVE-2016-8885 which complete the patch for CVE-2016-8690.

CVE-2017-13748

It was discovered that jasper does not properly release memory used
to store image tile data when image decoding fails which may lead to
a denial-of-service.

CVE-2017-14132

A heap-based buffer over-read was found related to the
jas_image_ishomosamp function that could be triggered via a crafted
image file and may cause a denial-of-service (application crash) or
have other unspecified impact." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjasper-dev", ver: "1.900.1-debian1-2.4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjasper-runtime", ver: "1.900.1-debian1-2.4+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjasper1", ver: "1.900.1-debian1-2.4+deb8u4", rls: "DEB8" ) )){
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

