if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890929" );
	script_version( "2021-06-18T11:00:25+0000" );
	script_cve_id( "CVE-2015-8981", "CVE-2017-5852", "CVE-2017-5853", "CVE-2017-5854", "CVE-2017-5886", "CVE-2017-6844", "CVE-2017-7379" );
	script_name( "Debian LTS: Security Advisory for libpodofo (DLA-929-1)" );
	script_tag( name: "last_modification", value: "2021-06-18 11:00:25 +0000 (Fri, 18 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-17 00:00:00 +0100 (Wed, 17 Jan 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-03-21 19:05:00 +0000 (Tue, 21 Mar 2017)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/04/msg00048.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libpodofo on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.9.0-1.1+deb7u1.

We recommend that you upgrade your libpodofo packages." );
	script_tag( name: "summary", value: "Several heap-based buffer overflows, integer overflows and NULL pointer
dereferences have been discovered in libpodofo, a library for
manipulating PDF files, that allow remote attackers to cause a denial
of service (application crash) or other unspecified impact via a
crafted PDF document." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libpodofo-dev", ver: "0.9.0-1.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpodofo-utils", ver: "0.9.0-1.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpodofo0.9.0", ver: "0.9.0-1.1+deb7u1", rls: "DEB7" ) )){
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

