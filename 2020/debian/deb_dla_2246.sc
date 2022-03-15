if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892246" );
	script_version( "2021-07-26T11:00:54+0000" );
	script_cve_id( "CVE-2020-13696" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-26 11:00:54 +0000 (Mon, 26 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 03:15:00 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-06-13 03:00:10 +0000 (Sat, 13 Jun 2020)" );
	script_name( "Debian LTS: Security Advisory for xawtv (DLA-2246-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00018.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2246-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/962221" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xawtv'
  package(s) announced via the DLA-2246-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "An issue was discovered in LinuxTV xawtv before 3.107. The function
dev_open() in v4l-conf.c does not perform sufficient checks to
prevent an unprivileged caller of the program from opening unintended
filesystem paths. This allows a local attacker with access to the
v4l-conf setuid-root program to test for the existence of arbitrary
files and to trigger an open on arbitrary files with mode O_RDWR.
To achieve this, relative path components need to be added to the
device path, as demonstrated by a
v4l-conf -c /dev/../root/.bash_history command." );
	script_tag( name: "affected", value: "'xawtv' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
3.103-3+deb8u1.

We recommend that you upgrade your xawtv packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "alevtd", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "fbtv", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "pia", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "radio", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "scantv", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "streamer", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "ttv", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "v4l-conf", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "webcam", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xawtv", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xawtv-dbg", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xawtv-plugin-qt", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xawtv-plugins", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xawtv-tools", ver: "3.103-3+deb8u1", rls: "DEB8" ) )){
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

