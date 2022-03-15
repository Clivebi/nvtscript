if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891290" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2017-13194" );
	script_name( "Debian LTS: Security Advisory for libvpx (DLA-1290-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-27 00:00:00 +0200 (Tue, 27 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-24 00:15:00 +0000 (Fri, 24 Jul 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/02/msg00025.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "libvpx on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.1.0-1+deb7u1.

We recommend that you upgrade your libvpx packages." );
	script_tag( name: "summary", value: "CVE-2017-13194
Fix for a flaw in libvpx related to odd frame width, which may lead
to a denial of service." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvpx-dev", ver: "1.1.0-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx-doc", ver: "1.1.0-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx1", ver: "1.1.0-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvpx1-dbg", ver: "1.1.0-1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "vpx-tools", ver: "1.1.0-1+deb7u1", rls: "DEB7" ) )){
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

