if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.704137" );
	script_version( "2021-06-21T12:14:05+0000" );
	script_cve_id( "CVE-2018-1064", "CVE-2018-5748", "CVE-2018-6764" );
	script_name( "Debian Security Advisory DSA 4137-1 (libvirt - security update)" );
	script_tag( name: "last_modification", value: "2021-06-21 12:14:05 +0000 (Mon, 21 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-14 00:00:00 +0100 (Wed, 14 Mar 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-20 01:29:00 +0000 (Wed, 20 Jun 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2018/dsa-4137.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(9|8)" );
	script_tag( name: "affected", value: "libvirt on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (jessie), these problems have been fixed
in version 1.2.9-9+deb8u5.

For the stable distribution (stretch), these problems have been fixed in
version 3.0.0-4+deb9u3.

We recommend that you upgrade your libvirt packages." );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/libvirt" );
	script_tag( name: "summary", value: "Several vulnerabilities were discovered in Libvirt, a virtualisation
abstraction library:

CVE-2018-1064
Daniel Berrange discovered that the QEMU guest agent performed
insufficient validation of incoming data, which allows a privileged
user in the guest to exhaust resources on the virtualisation host,
resulting in denial of service.

CVE-2018-5748
Daniel Berrange and Peter Krempa that the QEMU monitor was suspectible
to denial of service by memory exhaustion. This was already fixed in
Debian stretch and only affects Debian jessie.

CVE-2018-6764
Pedro Sampaio discovered that LXC containers detected the hostname
insecurely. This only affects Debian stretch." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libnss-libvirt", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-clients", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon-system", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-dev", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-doc", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-sanlock", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt0", ver: "3.0.0-4+deb9u3", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-clients", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-daemon-system", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-dev", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-doc", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt-sanlock", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvirt0-dbg", ver: "1.2.9-9+deb8u5", rls: "DEB8" ) )){
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

