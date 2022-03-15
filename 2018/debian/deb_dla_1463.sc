if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891463" );
	script_version( "2021-06-18T02:00:26+0000" );
	script_cve_id( "CVE-2018-12578", "CVE-2018-12601" );
	script_name( "Debian LTS: Security Advisory for sam2p (DLA-1463-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 02:00:26 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-13 00:00:00 +0200 (Mon, 13 Aug 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00010.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "sam2p on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.49.2-3+deb8u3.

We recommend that you upgrade your sam2p packages." );
	script_tag( name: "summary", value: "Various vulnerabilities leading to denial of service or possible unspecified
other impacts were discovered in sam2p, an utility to convert raster images to
EPS, PDF, and other formats.

CVE-2018-12578

A heap-buffer-overflow in bmp_compress1_row. Thanks to Peter Szabo for
providing a fix.

CVE-2018-12601

A heap-buffer-overflow in function ReadImage, in file input-tga.ci. Thanks
to Peter Szabo for providing a fix." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "sam2p", ver: "0.49.2-3+deb8u3", rls: "DEB8" ) )){
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

