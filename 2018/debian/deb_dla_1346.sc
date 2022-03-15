if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891346" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2018-7456" );
	script_name( "Debian LTS: Security Advisory for tiff (DLA-1346-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-16 00:00:00 +0200 (Mon, 16 Apr 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-29 20:15:00 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/04/msg00010.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "tiff on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
4.0.2-6+deb7u19.

We recommend that you upgrade your tiff packages." );
	script_tag( name: "summary", value: "ULL Pointer Dereference was discovered in the TIFFPrintDirectory
function (tif_print.c) when using the tiffinfo tool to print crafted
TIFF information. This vulnerability could be leveraged by remote
attackers to cause a crash of the application." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtiff-doc", ver: "4.0.2-6+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "4.0.2-6+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff-tools", ver: "4.0.2-6+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5", ver: "4.0.2-6+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5-alt-dev", ver: "4.0.2-6+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff5-dev", ver: "4.0.2-6+deb7u19", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiffxx5", ver: "4.0.2-6+deb7u19", rls: "DEB7" ) )){
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

