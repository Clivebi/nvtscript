if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891865" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2018-3977", "CVE-2019-12216", "CVE-2019-12217", "CVE-2019-12218", "CVE-2019-12219", "CVE-2019-12220", "CVE-2019-12221", "CVE-2019-12222", "CVE-2019-5051", "CVE-2019-5052", "CVE-2019-7635" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-28 02:00:18 +0000 (Sun, 28 Jul 2019)" );
	script_name( "Debian LTS: Security Advisory for sdl-image1.2 (DLA-1865-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/07/msg00026.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1865-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sdl-image1.2'
  package(s) announced via the DLA-1865-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following issues have been found in sdl-image1.2, the 1.x version of the
image file loading library.

CVE-2018-3977

Heap buffer overflow in IMG_xcf.c. This vulnerability might be leveraged by
remote attackers to cause remote code execution or denial of service via a
crafted XCF file.

CVE-2019-5051

Heap based buffer overflow in IMG_LoadPCX_RW, in IMG_pcx.c. This
vulnerability might be leveraged by remote attackers to cause remote code
execution or denial of service via a crafted PCX file.

CVE-2019-5052

Integer overflow and subsequent buffer overflow in IMG_pcx.c. This
vulnerability might be leveraged by remote attackers to cause remote code
execution or denial of service via a crafted PCX file.

CVE-2019-7635

Heap buffer overflow affecting Blit1to4, in IMG_bmp.c. This vulnerability
might be leveraged by remote attackers to cause denial of service or any
other unspecified impact via a crafted BMP file.

CVE-2019-12216,
CVE-2019-12217,
CVE-2019-12218,
CVE-2019-12219,
CVE-2019-12220,
CVE-2019-12221,
CVE-2019-12222

Multiple out-of-bound read and write accesses affecting IMG_LoadPCX_RW, in
IMG_pcx.c. These vulnerabilities might be leveraged by remote attackers to
cause denial of service or any other unspecified impact via a crafted PCX
file." );
	script_tag( name: "affected", value: "'sdl-image1.2' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.2.12-5+deb8u2.

We recommend that you upgrade your sdl-image1.2 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2", ver: "1.2.12-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2-dbg", ver: "1.2.12-5+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsdl-image1.2-dev", ver: "1.2.12-5+deb8u2", rls: "DEB8" ) )){
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
exit( 0 );

