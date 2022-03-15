if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703613" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-5008" );
	script_name( "Debian Security Advisory DSA 3613-1 (libvirt - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-02 00:00:00 +0200 (Sat, 02 Jul 2016)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3613.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "libvirt on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.2.9-9+deb8u3.

For the unstable distribution (sid), this problem has been fixed in
version 2.0.0-1.

We recommend that you upgrade your libvirt packages." );
	script_tag( name: "summary", value: "Vivian Zhang and Christoph Anton
Mitterer discovered that setting an empty VNC password does not work as documented
in Libvirt, a virtualisation abstraction library. When the password on a VNC
server is set to the empty string, authentication on the VNC server will be
disabled, allowing any user to connect, despite the documentation
declaring that setting an empty password for the VNC server prevents all
client connections. With this update the behaviour is enforced by
setting the password expiration to now
." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-clients", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-daemon", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-daemon-system", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-dev", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-doc", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt-sanlock", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "libvirt0-dbg", ver: "1.2.9-9+deb8u3", rls: "DEB8" ) ) != NULL){
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
