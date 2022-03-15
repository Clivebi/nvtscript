if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892264" );
	script_version( "2021-07-23T02:01:00+0000" );
	script_cve_id( "CVE-2019-20839", "CVE-2020-14397", "CVE-2020-14399", "CVE-2020-14400", "CVE-2020-14401", "CVE-2020-14402", "CVE-2020-14403", "CVE-2020-14404", "CVE-2020-14405" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-23 02:01:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-29 00:15:00 +0000 (Sat, 29 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-07-01 03:02:32 +0000 (Wed, 01 Jul 2020)" );
	script_name( "Debian LTS: Security Advisory for libvncserver (DLA-2264-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2020/06/msg00035.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2264-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvncserver'
  package(s) announced via the DLA-2264-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in libVNC (libvncserver Debian package), an
implemenantation of the VNC server and client protocol.

CVE-2019-20839

libvncclient/sockets.c in LibVNCServer had a buffer overflow via a
long socket filename.

CVE-2020-14397

libvncserver/rfbregion.c had a NULL pointer dereference.

CVE-2020-14399

Byte-aligned data was accessed through uint32_t pointers in
libvncclient/rfbproto.c.

CVE-2020-14400

Byte-aligned data was accessed through uint16_t pointers in
libvncserver/translate.c.

CVE-2020-14401

libvncserver/scale.c had a pixel_value integer overflow.

CVE-2020-14402

libvncserver/corre.c allowed out-of-bounds access via encodings.

CVE-2020-14403

libvncserver/hextile.c allowed out-of-bounds access via encodings.

CVE-2020-14404

libvncserver/rre.c allowed out-of-bounds access via encodings.

CVE-2020-14405

libvncclient/rfbproto.c does not limit TextChat size." );
	script_tag( name: "affected", value: "'libvncserver' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
0.9.9+dfsg2-6.1+deb8u8.

We recommend that you upgrade your libvncserver packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0", ver: "0.9.9+dfsg2-6.1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncclient0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-config", ver: "0.9.9+dfsg2-6.1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver-dev", ver: "0.9.9+dfsg2-6.1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0", ver: "0.9.9+dfsg2-6.1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libvncserver0-dbg", ver: "0.9.9+dfsg2-6.1+deb8u8", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linuxvnc", ver: "0.9.9+dfsg2-6.1+deb8u8", rls: "DEB8" ) )){
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

