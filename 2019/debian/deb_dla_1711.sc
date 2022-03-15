if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891711" );
	script_version( "2021-09-03T13:01:29+0000" );
	script_cve_id( "CVE-2018-16864", "CVE-2019-3815" );
	script_name( "Debian LTS: Security Advisory for systemd (DLA-1711-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 13:01:29 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-13 00:00:00 +0100 (Wed, 13 Mar 2019)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 15:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/03/msg00013.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "systemd on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', this problem has been fixed in version
215-17+deb8u11.

We recommend that you upgrade your systemd packages." );
	script_tag( name: "summary", value: "memory leak was discovered in the backport of fixes for
CVE-2018-16864 in systemd-journald.

Function dispatch_message_real() in journald-server.c does not free
allocated memory to store the `_CMDLINE=` entry. A local attacker may
use this flaw to make systemd-journald crash.

Note that as the systemd-journald service is not restarted automatically
a restart of the service or more safely a reboot is advised." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "gir1.2-gudev-1.0", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgudev-1.0-0", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libgudev-1.0-dev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-systemd", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-daemon-dev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-daemon0", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-dev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-id128-0", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-id128-dev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-journal-dev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-journal0", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-login-dev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-login0", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd0", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libudev-dev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libudev1", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "python3-systemd", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-dbg", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-sysv", ver: "215-17+deb8u11", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "udev", ver: "215-17+deb8u11", rls: "DEB8" ) )){
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

