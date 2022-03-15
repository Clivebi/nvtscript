if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891638" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2016-3616", "CVE-2018-11212", "CVE-2018-11213", "CVE-2018-11214", "CVE-2018-1152" );
	script_name( "Debian LTS: Security Advisory for libjpeg-turbo (DLA-1638-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-23 00:00:00 +0100 (Wed, 23 Jan 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-06 17:15:00 +0000 (Tue, 06 Aug 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libjpeg-turbo on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1:1.3.1-12+deb8u1.

We recommend that you upgrade your libjpeg-turbo packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been resolved in libjpeg-turbo, Debian's
default JPEG implementation.

CVE-2016-3616

The cjpeg utility in libjpeg allowed remote attackers to cause a
denial of service (NULL pointer dereference and application crash) or
execute arbitrary code via a crafted file.

This issue got fixed by the same patch that fixed CVE-2018-11213 and
CVE-2018-11214.

CVE-2018-1152

libjpeg-turbo has been found vulnerable to a denial of service
vulnerability caused by a divide by zero when processing a crafted
BMP image. The issue has been resolved by a boundary check.

CVE-2018-11212

The alloc_sarray function in jmemmgr.c allowed remote attackers to
cause a denial of service (divide-by-zero error) via a crafted file.

The issue has been addressed by checking the image size when reading
a targa file and throwing an error when image width or height is 0.

CVE-2018-11213
CVE-2018-11214

The get_text_gray_row and get_text_rgb_row functions in rdppm.c both
allowed remote attackers to cause a denial of service (Segmentation
fault) via a crafted file.

By checking the range of integer values in PPM text files and adding
checks to ensure values are within the specified range, both issues" );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libjpeg-dev", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg-turbo-progs", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg-turbo-progs-dbg", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg62-turbo", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg62-turbo-dbg", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libjpeg62-turbo-dev", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libturbojpeg1", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libturbojpeg1-dbg", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libturbojpeg1-dev", ver: "1:1.3.1-12+deb8u1", rls: "DEB8" ) )){
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

