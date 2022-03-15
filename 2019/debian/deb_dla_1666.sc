if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891666" );
	script_version( "2021-09-02T14:01:33+0000" );
	script_cve_id( "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789" );
	script_name( "Debian LTS: Security Advisory for freerdp (DLA-1666-1)" );
	script_tag( name: "last_modification", value: "2021-09-02 14:01:33 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-02-11 00:00:00 +0100 (Mon, 11 Feb 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 02:09:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2019/02/msg00015.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "freerdp on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these security problems have been fixed in version
1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3.

We recommend that you upgrade your freerdp packages." );
	script_tag( name: "summary", value: "For the FreeRDP version in Debian jessie LTS a security and functionality
update has recently been provided. FreeRDP is a free re-implementation
of the Microsoft RDP protocol (server and client side) with freerdp-x11
being the most common RDP client these days.

Functional improvements:

With help from FreeRDP upstream (cudos to Bernhard Miklautz and
Martin Fleisz) we are happy to announce that RDP proto v6 and CredSSP
v3 support have been backported to the old FreeRDP 1.1 branch.

Since Q2/2018, Microsoft Windows servers and clients received an
update that defaulted their RDP server to proto version 6. Since this
change, people have not been able anymore to connect to recently
updated MS Windows machines using old the FreeRDP 1.1 branch as found
in Debian jessie LTS and Debian stretch.

With the recent FreeRDP upload to Debian jessie LTS, connecting to
up-to-date MS Windows machines is now again possible.

Security issues:

CVE-2018-8786

FreeRDP contained an integer truncation that lead to a heap-based
buffer overflow in function update_read_bitmap_update() and resulted
in a memory corruption and probably even a remote code execution.

CVE-2018-8787

FreeRDP contained an integer overflow that leads to a heap-based
buffer overflow in function gdi_Bitmap_Decompress() and resulted in a
memory corruption and probably even a remote code execution.

CVE-2018-8788

FreeRDP contained an out-of-bounds write of up to 4 bytes in function
nsc_rle_decode() that resulted in a memory corruption and possibly
even a remote code execution.

CVE-2018-8789

FreeRDP contained several out-of-bounds reads in the NTLM
authentication module that resulted in a denial of service
(segfault)." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "freerdp-x11", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "freerdp-x11-dbg", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-cache1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-client1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-codec1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-common1.1.0", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-core1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-crypto1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-dbg", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-dev", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-gdi1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-locale1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-plugins-standard", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-plugins-standard-dbg", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-primitives1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-rail1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-utils1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-asn1-0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-bcrypt0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-credentials0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-credui0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-crt0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-crypto0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-dbg", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-dev", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-dsparse0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-environment0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-error0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-file0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-handle0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-heap0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-input0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-interlocked0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-io0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-library0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-path0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-pipe0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-pool0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-registry0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-rpc0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-sspi0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-sspicli0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-synch0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-sysinfo0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-thread0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-timezone0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-utils0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-winhttp0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libwinpr-winsock0.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxfreerdp-client-dbg", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libxfreerdp-client1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-13~deb8u3", rls: "DEB8" ) )){
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

