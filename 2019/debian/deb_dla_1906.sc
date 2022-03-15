if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891906" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-20852" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-22 17:15:00 +0000 (Sat, 22 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-01 02:00:09 +0000 (Sun, 01 Sep 2019)" );
	script_name( "Debian LTS: Security Advisory for python2.7 (DLA-1906-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/08/msg00040.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-1906-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python2.7'
  package(s) announced via the DLA-1906-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A vulnerability has been discovered in Python, an interactive high-level
object-oriented language, that is relevant for cookie handling. By using a
malicious server an attacker might steal cookies that are meant for other
domains" );
	script_tag( name: "affected", value: "'python2.7' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
2.7.9-2+deb8u4.

We recommend that you upgrade your python2.7 packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "idle-python2.7", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-dbg", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-dev", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-minimal", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-stdlib", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpython2.7-testsuite", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-dbg", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-dev", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-doc", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-examples", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python2.7-minimal", ver: "2.7.9-2+deb8u4", rls: "DEB8" ) )){
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

