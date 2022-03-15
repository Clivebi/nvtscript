if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892715" );
	script_version( "2021-08-25T09:01:10+0000" );
	script_cve_id( "CVE-2021-33910" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-25 09:01:10 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-29 17:50:00 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-21 03:00:15 +0000 (Wed, 21 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for systemd (DLA-2715-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2715-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2715-1" );
	script_xref( name: "URL", value: "https://www.qualys.com/2021/07/20/cve-2021-33910/denial-of-service-systemd.txt" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'systemd'
  package(s) announced via the DLA-2715-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Qualys Research Labs discovered that an attacker-controlled
allocation using the alloca() function could result in memory
corruption, allowing to crash systemd and hence the entire operating
system.

Details can be found in the Qualys advisory at
[link moved to references]" );
	script_tag( name: "affected", value: "'systemd' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, this problem has been fixed in version
232-25+deb9u13.

We recommend that you upgrade your systemd packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnss-myhostname", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-mymachines", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-resolve", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libnss-systemd", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libpam-systemd", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd-dev", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libsystemd0", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libudev-dev", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libudev1", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-container", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-coredump", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-journal-remote", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "systemd-sysv", ver: "232-25+deb9u13", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "udev", ver: "232-25+deb9u13", rls: "DEB9" ) )){
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

