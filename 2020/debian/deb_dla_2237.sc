if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892237" );
	script_version( "2021-07-23T11:01:09+0000" );
	script_cve_id( "CVE-2019-8842", "CVE-2020-3898" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 11:01:09 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 20:00:00 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-06-08 03:00:09 +0000 (Mon, 08 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for cups (DLA-2237-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00005.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2237-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups'
  package(s) announced via the DLA-2237-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The following CVE(s) were reported against src:cups.

CVE-2019-8842

The `ippReadIO` function may under-read an extension field.

CVE-2020-3898

There was a heap based buffer overflow in libcups's
ppdFindOption() in ppd-mark.c.
The `ppdOpen` function did not handle invalid UI constraint.
`ppdcSource::get_resolution` function did not handle invalid
resolution strings." );
	script_tag( name: "affected", value: "'cups' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
1.7.5-11+deb8u8.

We recommend that you upgrade your cups packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cups", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-client", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-common", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-core-drivers", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-daemon", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-server-common", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.7.5-11+deb8u8", rls: "DEB8" ) )){
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
exit( 0 );

