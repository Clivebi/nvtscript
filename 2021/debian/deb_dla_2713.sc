if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892713" );
	script_version( "2021-08-24T14:01:01+0000" );
	script_cve_id( "CVE-2021-21781", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3609" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 14:01:01 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-29 17:46:00 +0000 (Thu, 29 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-21 03:00:18 +0000 (Wed, 21 Jul 2021)" );
	script_name( "Debian LTS: Security Advisory for linux (DLA-2713-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/07/msg00014.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2713-1" );
	script_xref( name: "Advisory-ID", value: "DLA-2713-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/990072" );
	script_xref( name: "URL", value: "https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the DLA-2713-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "CVE-2021-3609

Norbert Slusarek reported a race condition vulnerability in the CAN
BCM networking protocol, allowing a local attacker to escalate
privileges.

CVE-2021-21781

'Lilith >_>' of Cisco Talos discovered that the Arm initialisation
code does not fully initialise the 'sigpage' that is mapped into
user-space processes to support signal handling. This could
result in leaking sensitive information, particularly when the
system is rebooted.

CVE-2021-33909

The Qualys Research Labs discovered a size_t-to-int conversion
vulnerability in the Linux kernel's filesystem layer. An
unprivileged local attacker able to create, mount, and then delete a
deep directory structure whose total path length exceeds 1GB, can
take advantage of this flaw for privilege escalation.

Details can be found in the Qualys advisory at
[link moved to references]

CVE-2021-34693

Norbert Slusarek discovered an information leak in the CAN BCM
networking protocol. A local attacker can take advantage of this
flaw to obtain sensitive information from kernel stack memory." );
	script_tag( name: "affected", value: "'linux' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
4.9.272-2.

We recommend that you upgrade your linux packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "hyperv-daemons", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcpupower-dev", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libcpupower1", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libusbip-dev", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-arm", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-compiler-gcc-6-x86", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-cpupower", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-doc-4.9", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-686", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-all", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-all-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-all-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-all-armel", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-all-armhf", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-all-i386", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-armmp", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-armmp-lpae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-common", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-common-rt", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-marvell", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-rt-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-14-rt-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-686", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-all", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-all-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-all-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-all-armel", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-all-armhf", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-all-i386", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-armmp", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-armmp-lpae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-common", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-common-rt", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-marvell", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-rt-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-15-rt-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-686", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-all", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-all-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-all-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-all-armel", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-all-armhf", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-all-i386", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-armmp", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-armmp-lpae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-common", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-common-rt", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-marvell", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-rt-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-headers-4.9.0-16-rt-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-686", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-686-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-686-pae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-amd64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-arm64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-armmp", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-armmp-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-armmp-lpae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-armmp-lpae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-marvell", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-marvell-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-rt-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-rt-686-pae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-rt-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-14-rt-amd64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-686", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-686-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-686-pae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-amd64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-arm64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-armmp", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-armmp-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-armmp-lpae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-armmp-lpae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-marvell", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-marvell-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-rt-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-rt-686-pae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-rt-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-15-rt-amd64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-686", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-686-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-686-pae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-amd64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-arm64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-arm64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-armmp", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-armmp-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-armmp-lpae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-armmp-lpae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-marvell", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-marvell-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-rt-686-pae", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-rt-686-pae-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-rt-amd64", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.9.0-16-rt-amd64-dbg", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-kbuild-4.9", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-libc-dev", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-manual-4.9", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-perf-4.9", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-source-4.9", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-14", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-15", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "linux-support-4.9.0-16", ver: "4.9.272-2", rls: "DEB9" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "usbip", ver: "4.9.272-2", rls: "DEB9" ) )){
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

