if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891094" );
	script_version( "2021-06-17T02:00:27+0000" );
	script_cve_id( "CVE-2017-11335" );
	script_name( "Debian LTS: Security Advisory for tiff3 (DLA-1094-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 02:00:27 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-07 00:00:00 +0100 (Wed, 07 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-22 01:29:00 +0000 (Thu, 22 Mar 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/09/msg00011.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "tiff3 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.9.6-11+deb7u8.

We recommend that you upgrade your tiff3 packages." );
	script_tag( name: "summary", value: "heap based buffer overflow has been discovered in the tiff2pdf
utility, part of the Tag Image File Format (TIFF) library.

A PlanarConfig=Contig image can cause an out-of-bounds write (related to
the ZIPDecode function). A crafted input may lead to a remote denial of
service attack or an arbitrary code execution attack." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.6-11+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.6-11+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.6-11+deb7u8", rls: "DEB7" ) )){
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
