if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704003" );
	script_version( "2021-09-14T09:01:51+0000" );
	script_cve_id( "CVE-2017-1000256" );
	script_name( "Debian Security Advisory DSA 4003-1 (libvirt - security update)" );
	script_tag( name: "last_modification", value: "2021-09-14 09:01:51 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-19 00:00:00 +0200 (Thu, 19 Oct 2017)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-16 20:21:00 +0000 (Mon, 16 Nov 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2017/dsa-4003.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_tag( name: "affected", value: "libvirt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (stretch), this problem has been fixed in
version 3.0.0-4+deb9u1.

For the unstable distribution (sid), this problem has been fixed in
version 3.8.0-3.

We recommend that you upgrade your libvirt packages." );
	script_tag( name: "summary", value: "Daniel P. Berrange reported that Libvirt, a virtualisation abstraction
library, does not properly handle the default_tls_x509_verify (and
related) parameters in qemu.conf when setting up TLS clients and servers
in QEMU, resulting in TLS clients for character devices and disk devices
having verification turned off and ignoring any errors while validating
the server certificate." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libnss-libvirt", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-clients", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-daemon-system", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-dev", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-doc", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-sanlock", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0", ver: "3.0.0-4+deb9u1", rls: "DEB9" ) ) != NULL){
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

