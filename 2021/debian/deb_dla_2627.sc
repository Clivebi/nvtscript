if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892627" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-3472" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-19 12:54:00 +0000 (Wed, 19 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 03:00:06 +0000 (Fri, 16 Apr 2021)" );
	script_name( "Debian LTS: Security Advisory for xorg-server (DLA-2627-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/04/msg00013.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2627-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2627-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-server'
  package(s) announced via the DLA-2627-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Jan-Niklas Sohn discovered that there was an input validation failure
in the X.Org display server.

Insufficient checks on the lengths of the XInput extension's
ChangeFeedbackControl request could have lead to out of bounds memory
accesses in the X server. These issues can lead to privilege
escalation for authorised clients, particularly on systems where the
X server is running as a privileged user." );
	script_tag( name: "affected", value: "'xorg-server' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 'Stretch', this problem has been fixed in version
2:1.19.2-1+deb9u8.

We recommend that you upgrade your xorg-server packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "xdmx", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xdmx-tools", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xnest", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xorg-server-source", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xserver-common", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xserver-xephyr", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-core", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-dev", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xserver-xorg-legacy", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xvfb", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "xwayland", ver: "2:1.19.2-1+deb9u8", rls: "DEB9" ) )){
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

