if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891496" );
	script_version( "2021-06-17T11:00:26+0000" );
	script_cve_id( "CVE-2018-16435" );
	script_name( "Debian LTS: Security Advisory for lcms2 (DLA-1496-1)" );
	script_tag( name: "last_modification", value: "2021-06-17 11:00:26 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-06 00:00:00 +0200 (Thu, 06 Sep 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 11:15:00 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/09/msg00005.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "lcms2 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this issue has been fixed in lcms2 version
2.6-3+deb8u2.

We recommend that you upgrade your lcms2 packages." );
	script_tag( name: "summary", value: "It was discovered that there was an integer overflow vulnerability
in the 'Little CMS 2' colour management library. A specially-crafted
input file could lead to a heap-based buffer overflow." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "liblcms2-2", ver: "2.6-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblcms2-dbg", ver: "2.6-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblcms2-dev", ver: "2.6-3+deb8u2", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "liblcms2-utils", ver: "2.6-3+deb8u2", rls: "DEB8" ) )){
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

