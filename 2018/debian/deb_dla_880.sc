if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890880" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-8784", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535" );
	script_name( "Debian LTS: Security Advisory for tiff3 (DLA-880-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-12 00:00:00 +0100 (Fri, 12 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/03/msg00039.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "tiff3 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.9.6-11+deb7u4.

We recommend that you upgrade your tiff3 packages." );
	script_tag( name: "summary", value: "tiff3 is affected by multiple issues that can result at least in denial of
services of applications using libtiff4. Crafted TIFF files can be
provided to trigger: abort() calls via failing assertions, buffer overruns
(both in read and write mode).

CVE-2015-8781

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds write) via an invalid number of samples per pixel in a
LogL compressed TIFF image.

CVE-2015-8782

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds writes) via a crafted TIFF image.

CVE-2015-8783

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds reads) via a crafted TIFF image.

CVE-2015-8784

The NeXTDecode function in tif_next.c in LibTIFF allows remote
attackers to cause a denial of service (out-of-bounds write) via a
crafted TIFF image.

CVE-2016-9533

tif_pixarlog.c in libtiff 4.0.6 has out-of-bounds write
vulnerabilities in heap allocated buffers.

CVE-2016-9534

tif_write.c in libtiff 4.0.6 has an issue in the error code path of
TIFFFlushData1() that didn't reset the tif_rawcc and tif_rawcp
members.

CVE-2016-9535

tif_predict.h and tif_predict.c in libtiff 4.0.6 have assertions
that can lead to assertion failures in debug mode, or buffer
overflows in release mode, when dealing with unusual tile size
like YCbCr with subsampling." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.6-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.6-11+deb7u4", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.6-11+deb7u4", rls: "DEB7" ) )){
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

