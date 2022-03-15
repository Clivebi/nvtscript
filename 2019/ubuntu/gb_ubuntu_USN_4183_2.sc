if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844277" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_cve_id( "CVE-2019-0155", "CVE-2019-11135", "CVE-2018-12207", "CVE-2019-0154", "CVE-2019-15791", "CVE-2019-15792", "CVE-2019-15793", "CVE-2019-16746", "CVE-2019-17666" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-24 19:15:00 +0000 (Thu, 24 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-12-12 03:01:20 +0000 (Thu, 12 Dec 2019)" );
	script_name( "Ubuntu Update for linux USN-4183-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU19\\.10" );
	script_xref( name: "USN", value: "4183-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005204.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4183-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4183-1 fixed vulnerabilities in the Linux kernel. It was
discovered that the kernel fix for CVE-2019-0155 (i915 missing Blitter
Command Streamer check) was incomplete on 64-bit Intel x86 systems.
This update addresses the issue.

We apologize for the inconvenience.

Original advisory details:

Stephan van Schaik, Alyssa Milburn, Sebastian Österlund, Pietro Frigo,
Kaveh Razavi, Herbert Bos, Cristiano Giuffrida, Giorgi Maisuradze, Moritz
Lipp, Michael Schwarz, Daniel Gruss, and Jo Van Bulck discovered that Intel
processors using Transactional Synchronization Extensions (TSX) could
expose memory contents previously stored in microarchitectural buffers to a
malicious process that is executing on the same CPU core. A local attacker
could use this to expose sensitive information. (CVE-2019-11135)

It was discovered that the Intel i915 graphics chipsets allowed userspace
to modify page table entries via writes to MMIO from the Blitter Command
Streamer and expose kernel memory information. A local attacker could use
this to expose sensitive information or possibly elevate privileges.
(CVE-2019-0155)

Deepak Gupta discovered that on certain Intel processors, the Linux kernel
did not properly perform invalidation on page table updates by virtual
guest operating systems. A local attacker in a guest VM could use this to
cause a denial of service (host system crash). (CVE-2018-12207)

It was discovered that the Intel i915 graphics chipsets could cause a
system hang when userspace performed a read from GT memory mapped input
output (MMIO) when the product is in certain low power states. A local
attacker could use this to cause a denial of service. (CVE-2019-0154)

Jann Horn discovered a reference count underflow in the shiftfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15791)

Jann Horn discovered a type confusion vulnerability in the shiftfs
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2019-15792)

Jann Horn discovered that the shiftfs implementation in the Linux kernel
did not use the correct file system uid/gid when the user namespace of a
lower file system is not in the init user namespace. A local attacker could
use this to possibly bypass DAC permissions or have some other unspecified
impact. (CVE-2019-15793)

It was discovered that a buffer overflow existed in the 802.11 Wi-Fi
configuration interface for the Linux kernel when handling beacon settings.
A local attacker could use ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 19.10." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU19.10"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-23-generic", ver: "5.3.0-23.25", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-23-generic-lpae", ver: "5.3.0-23.25", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-23-lowlatency", ver: "5.3.0-23.25", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-5.3.0-23-snapdragon", ver: "5.3.0-23.25", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "5.3.0.23.27", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "5.3.0.23.27", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "5.3.0.23.27", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-snapdragon", ver: "5.3.0.23.27", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "5.3.0.23.27", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "Please", ver: "note that mitigating the TSX (CVE-2019-11135) and i915", rls: "UBUNTU19.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "firmware", ver: "updates respectively.", rls: "UBUNTU19.10" ) )){
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
}
exit( 0 );

