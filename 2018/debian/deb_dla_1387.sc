if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891387" );
	script_version( "2021-06-21T11:00:26+0000" );
	script_cve_id( "CVE-2017-18248" );
	script_name( "Debian LTS: Security Advisory for cups (DLA-1387-1)" );
	script_tag( name: "last_modification", value: "2021-06-21 11:00:26 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-28 00:00:00 +0200 (Mon, 28 May 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-13 01:29:00 +0000 (Fri, 13 Jul 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/05/msg00018.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "cups on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.5.3-5+deb7u8.

We recommend that you upgrade your cups packages." );
	script_tag( name: "summary", value: "CVE-2017-18248
It was found that by submitting a print job with an invalid username,
the CUPS server can be crashed, when D-Bus support is enabled (which
is the case for Debian)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cups", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-client", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-common", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cupsddk", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsdriver1", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsdriver1-dev", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.5.3-5+deb7u8", rls: "DEB7" ) )){
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

