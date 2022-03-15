if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891680" );
	script_version( "2021-09-06T10:01:39+0000" );
	script_cve_id( "CVE-2018-17000", "CVE-2018-19210", "CVE-2019-7663" );
	script_name( "Debian LTS: Security Advisory for tiff (DLA-1680-1)" );
	script_tag( name: "last_modification", value: "2021-09-06 10:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-18 00:00:00 +0100 (Mon, 18 Feb 2019)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 21:29:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00026.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "tiff on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.0.3-12.3+deb8u8.

We recommend that you upgrade your tiff packages." );
	script_tag( name: "summary", value: "Brief introduction

CVE-2018-17000

A NULL pointer dereference in the function _TIFFmemcmp at tif_unix.c
(called from TIFFWriteDirectoryTagTransferfunction) allows an
attacker to cause a denial-of-service through a crafted tiff file. This
vulnerability can be triggered by the executable tiffcp.

CVE-2018-19210

There is a NULL pointer dereference in the TIFFWriteDirectorySec function
in tif_dirwrite.c that will lead to a denial of service attack, as
demonstrated by tiffset.

CVE-2019-7663

An Invalid Address dereference was discovered in
TIFFWriteDirectoryTagTransferfunction in libtiff/tif_dirwrite.c,
affecting the cpSeparateBufToContigBuf function in tiffcp.c. Remote
attackers could leverage this vulnerability to cause a denial-of-service
via a crafted tiff file.

We believe this is the same as CVE-2018-17000 (above)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtiff-doc", ver: "4.0.3-12.3+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "4.0.3-12.3+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-tools", ver: "4.0.3-12.3+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5", ver: "4.0.3-12.3+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5-dev", ver: "4.0.3-12.3+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiffxx5", ver: "4.0.3-12.3+deb8u8", rls: "DEB8" ) )){
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

