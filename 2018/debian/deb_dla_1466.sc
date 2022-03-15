if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.891466" );
	script_version( "2021-06-16T02:00:28+0000" );
	script_cve_id( "CVE-2018-13405", "CVE-2018-5390", "CVE-2018-5391" );
	script_name( "Debian LTS: Security Advisory for linux-4.9 (DLA-1466-1)" );
	script_tag( name: "last_modification", value: "2021-06-16 02:00:28 +0000 (Wed, 16 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-15 00:00:00 +0200 (Wed, 15 Aug 2018)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 16:14:00 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2018/08/msg00014.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "linux-4.9 on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 8 'Jessie', these problems have been fixed in version
4.9.110-3+deb9u2~deb8u1. This update includes fixes for several
regressions in the latest point release.

The earlier version 4.9.110-3+deb9u1~deb8u1 included all the above
fixes except for CVE-2018-5391, which may be mitigated as explained
above.

We recommend that you upgrade your linux-4.9 packages." );
	script_tag( name: "summary", value: "Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation or denial of service.

CVE-2018-5390 (SegmentSmack)

Juha-Matti Tilli discovered that a remote attacker can trigger the
worst case code paths for TCP stream reassembly with low rates of
specially crafted packets, leading to remote denial of service.

CVE-2018-5391 (FragmentSmack)

Juha-Matti Tilli discovered a flaw in the way the Linux kernel
handled reassembly of fragmented IPv4 and IPv6 packets. A remote
attacker can take advantage of this flaw to trigger time and
calculation expensive fragment reassembly algorithms by sending
specially crafted packets, leading to remote denial of service.

This is mitigated by reducing the default limits on memory usage
for incomplete fragmented packets. The same mitigation can be
achieved without the need to reboot, by setting the sysctls:

net.ipv4.ipfrag_high_thresh = 262144

net.ipv6.ip6frag_high_thresh = 262144

net.ipv4.ipfrag_low_thresh = 196608

net.ipv6.ip6frag_low_thresh = 196608

The default values may still be increased by local configuration
if necessary.

CVE-2018-13405

Jann Horn discovered that the inode_init_owner function in
fs/inode.c in the Linux kernel allows local users to create files
with an unintended group ownership allowing attackers to escalate
privileges by making a plain file executable and SGID." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-4.9-arm", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-4.9", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-686", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-686-pae", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-amd64", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-armel", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-armhf", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-all-i386", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-amd64", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-armmp", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-armmp-lpae", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-common", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-common-rt", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-marvell", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-rt-686-pae", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-0.bpo.7-rt-amd64", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-686", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-686-pae", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-686-pae-dbg", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-amd64", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-amd64-dbg", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-armmp", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-armmp-lpae", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-marvell", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-686-pae", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-amd64", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-kbuild-4.9", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-4.9", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-perf-4.9", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-4.9", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-0.bpo.7", ver: "4.9.110-3+deb9u2~deb8u1", rls: "DEB8" ) )){
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

