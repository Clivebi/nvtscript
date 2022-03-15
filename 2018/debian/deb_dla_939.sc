if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890939" );
	script_version( "2021-06-15T11:41:24+0000" );
	script_cve_id( "CVE-2016-9603", "CVE-2017-7718", "CVE-2017-7980" );
	script_name( "Debian LTS: Security Advisory for qemu-kvm (DLA-939-1)" );
	script_tag( name: "last_modification", value: "2021-06-15 11:41:24 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-25 00:00:00 +0100 (Thu, 25 Jan 2018)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-07 10:29:00 +0000 (Fri, 07 Sep 2018)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/05/msg00010.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "qemu-kvm on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u21.

We recommend that you upgrade your qemu-kvm packages." );
	script_tag( name: "summary", value: "Multiple vulnerabilities have been discovered in qemu-kvm, a full
virtualization solution on x86 hardware based on Quick
Emulator(Qemu). The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2016-9603

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator and the VNC
display driver support is vulnerable to a heap buffer overflow
issue. It could occur when Vnc client attempts to update its
display after a vga operation is performed by a guest.

A privileged user/process inside guest could use this flaw to crash
the Qemu process resulting in DoS OR potentially leverage it to
execute arbitrary code on the host with privileges of the Qemu
process.

CVE-2017-7718

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator support is
vulnerable to an out-of-bounds access issue. It could occur while
copying VGA data via bitblt functions cirrus_bitblt_rop_fwd_transp_
and/or cirrus_bitblt_rop_fwd_.

A privileged user inside guest could use this flaw to crash the
Qemu process resulting in DoS.

CVE-2017-7980

qemu-kvm built with the Cirrus CLGD 54xx VGA Emulator support is
vulnerable to an out-of-bounds r/w access issues. It could occur
while copying VGA data via various bitblt functions.

A privileged user inside guest could use this flaw to crash the
Qemu process resulting in DoS OR potentially execute arbitrary code
on a host with privileges of Qemu process on the host." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "kvm", ver: "1.1.2+dfsg-6+deb7u21", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm", ver: "1.1.2+dfsg-6+deb7u21", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "qemu-kvm-dbg", ver: "1.1.2+dfsg-6+deb7u21", rls: "DEB7" ) )){
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

