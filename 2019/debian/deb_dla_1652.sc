if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891652" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2018-15126", "CVE-2018-15127", "CVE-2018-20019", "CVE-2018-20748", "CVE-2018-20749", "CVE-2018-20750" );
	script_name( "Debian LTS: Security Advisory for libvncserver (DLA-1652-1)" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-01-31 00:00:00 +0100 (Thu, 31 Jan 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-31 01:15:00 +0000 (Thu, 31 Oct 2019)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/01/msg00029.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libvncserver on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.9.9+dfsg2-6.1+deb8u5.

We recommend that you upgrade your libvncserver packages." );
	script_tag( name: "summary", value: "A vulnerability was found by Kaspersky Lab in libvncserver, a C library
to implement VNC server/client functionalities. In addition, some of the
vulnerabilities addressed in DLA 1617-1 were found to have incomplete
fixes, and have been addressed in this update.

CVE-2018-15126

An attacker can cause denial of service or remote code execution via
a heap use-after-free issue in the tightvnc-filetransfer extension.

CVE-2018-20748
CVE-2018-20749
CVE-2018-20750

Some of the out of bound heap write fixes for CVE-2018-20019 and
CVE-2018-15127 were incomplete. These CVEs address those issues." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0", ver: "0.9.9+dfsg2-6.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-config", ver: "0.9.9+dfsg2-6.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-dev", ver: "0.9.9+dfsg2-6.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.9+dfsg2-6.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linuxvnc", ver: "0.9.9+dfsg2-6.1+deb8u5", rls: "DEB8" ) )){
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

