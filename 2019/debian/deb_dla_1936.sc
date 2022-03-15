if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891936" );
	script_version( "2021-09-03T11:01:27+0000" );
	script_cve_id( "CVE-2018-4300" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 11:01:27 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-28 12:15:00 +0000 (Sat, 28 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-09-29 02:00:15 +0000 (Sun, 29 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for cups (DLA-1936-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/09/msg00028.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1936-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cups'
  package(s) announced via the DLA-1936-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue has been found in cups, the Common UNIX Printing System(tm).

While generating a session cookie for the CUPS web interface, a
predictable random number seed was used. This could lead to unauthorized
scripted access to the enabled web interface." );
	script_tag( name: "affected", value: "'cups' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie',
this problem has been fixed in version 1.7.5-11+deb8u6.

We recommend that you upgrade your cups packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "cups", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-bsd", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-client", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-common", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-core-drivers", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-daemon", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-dbg", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-ppdc", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "cups-server-common", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcups2-dev", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupscgi1-dev", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsimage2-dev", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsmime1-dev", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcupsppdc1-dev", ver: "1.7.5-11+deb8u6", rls: "DEB8" ) )){
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

