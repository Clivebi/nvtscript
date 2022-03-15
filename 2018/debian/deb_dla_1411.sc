if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891411" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2017-11613", "CVE-2017-13726", "CVE-2017-18013", "CVE-2018-10963", "CVE-2018-5784", "CVE-2018-7456", "CVE-2018-8905" );
	script_name( "Debian LTS: Security Advisory for tiff (DLA-1411-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/07/msg00002.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "tiff on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.0.3-12.3+deb8u6.

We recommend that you upgrade your tiff packages." );
	script_tag( name: "summary", value: "Several issues were discovered in TIFF, the Tag Image File Format
library, that allowed remote attackers to cause a denial-of-service or
other unspecified impact via a crafted image file.

CVE-2017-11613: DoS vulnerability
A crafted input will lead to a denial of service attack. During the
TIFFOpen process, td_imagelength is not checked. The value of
td_imagelength can be directly controlled by an input file. In the
ChopUpSingleUncompressedStrip function, the _TIFFCheckMalloc
function is called based on td_imagelength. If the value of
td_imagelength is set close to the amount of system memory, it will
hang the system or trigger the OOM killer.

CVE-2018-10963: DoS vulnerability
The TIFFWriteDirectorySec() function in tif_dirwrite.c in LibTIFF
allows remote attackers to cause a denial of service (assertion
failure and application crash) via a crafted file, a different
vulnerability than CVE-2017-13726.

CVE-2018-5784: DoS vulnerability
In LibTIFF, there is an uncontrolled resource consumption in the
TIFFSetDirectory function of tif_dir.c. Remote attackers could
leverage this vulnerability to cause a denial of service via a
crafted tif file.
This occurs because the declared number of directory entries is not
validated against the actual number of directory entries.

CVE-2018-7456: NULL Pointer Dereference
A NULL Pointer Dereference occurs in the function TIFFPrintDirectory
in tif_print.c in LibTIFF when using the tiffinfo tool to print
crafted TIFF information, a different vulnerability than
CVE-2017-18013. (This affects an earlier part of the
TIFFPrintDirectory function that was not addressed by the
CVE-2017-18013 patch.)

CVE-2018-8905: Heap-based buffer overflow
In LibTIFF, a heap-based buffer overflow occurs in the function
LZWDecodeCompat in tif_lzw.c via a crafted TIFF file, as
demonstrated by tiff2ps." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtiff-doc", ver: "4.0.3-12.3+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "4.0.3-12.3+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-tools", ver: "4.0.3-12.3+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5", ver: "4.0.3-12.3+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5-dev", ver: "4.0.3-12.3+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiffxx5", ver: "4.0.3-12.3+deb8u6", rls: "DEB8" ) )){
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

