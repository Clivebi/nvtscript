if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890983" );
	script_version( "2021-06-16T11:00:23+0000" );
	script_cve_id( "CVE-2016-10095", "CVE-2017-9147", "CVE-2017-9403", "CVE-2017-9404" );
	script_name( "Debian LTS: Security Advisory for tiff3 (DLA-983-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 11:00:23 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-29 20:15:00 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00012.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "tiff3 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
3.9.6-11+deb7u6.

We recommend that you upgrade your tiff3 packages." );
	script_tag( name: "summary", value: "tiff3 was affected by multiple memory leaks (CVE-2017-9403, CVE-2017-9404)
that could result in denial of service. Furthermore, while the current
version in Debian was already patched for _TIFFVGetField issues
(CVE-2016-10095, CVE-2017-9147), we replaced our Debian-specific patches
by the upstream provided patches to stay closer to upstream." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.6-11+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.6-11+deb7u6", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.6-11+deb7u6", rls: "DEB7" ) )){
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

