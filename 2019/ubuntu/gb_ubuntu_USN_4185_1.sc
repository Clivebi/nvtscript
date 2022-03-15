if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844230" );
	script_version( "2021-08-31T08:01:19+0000" );
	script_cve_id( "CVE-2019-11135", "CVE-2019-0155", "CVE-2018-12207", "CVE-2019-0154", "CVE-2019-15098", "CVE-2019-17052", "CVE-2019-17053", "CVE-2019-17054", "CVE-2019-17055", "CVE-2019-17056", "CVE-2019-17666" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-31 08:01:19 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-24 19:15:00 +0000 (Thu, 24 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-11-13 03:00:52 +0000 (Wed, 13 Nov 2019)" );
	script_name( "Ubuntu Update for linux USN-4185-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "4185-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-November/005196.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux'
  package(s) announced via the USN-4185-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Stephan van Schaik, Alyssa Milburn, Sebastian Österlund, Pietro Frigo,
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

Hui Peng discovered that the Atheros AR6004 USB Wi-Fi device driver for the
Linux kernel did not properly validate endpoint descriptors returned by the
device. A physically proximate attacker could use this to cause a denial of
service (system crash). (CVE-2019-15098)

Ori Nimron discovered that the AX25 network protocol implementation in the
Linux kernel did not properly perform permissions checks. A local attacker
could use this to create a raw socket. (CVE-2019-17052)

Ori Nimron discovered that the IEEE 802.15.4 Low-Rate Wireless network
protocol implementation in the Linux kernel did not properly perform
permissions checks. A local attacker could use this to create a raw socket.
(CVE-2019-17053)

Ori Nimron discovered that the Appletalk network protocol implementation in
the Linux kernel did not properly perform permissions checks. A local
attacker could use this to create a raw socket. (CVE-2019-17054)

Ori Nimron discovered that the modular ISDN network protocol implementation
in the Linux kernel did not properly perform permissions checks. A local
attacker could use this to create a raw socket. (CVE-2019-17055)

Ori Nimron discovered that the Near field Communication (NFC) network
protocol implementation in ...

  Description truncated. Please see the references for more information." );
	script_tag( name: "affected", value: "'linux' package(s) on Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1029-oracle", ver: "4.15.0-1029.32", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1048-gke", ver: "4.15.0-1048.51", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1050-kvm", ver: "4.15.0-1050.50", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1054-aws", ver: "4.15.0-1054.56", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1063-oem", ver: "4.15.0-1063.72", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-69-generic", ver: "4.15.0-69.78", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-69-generic-lpae", ver: "4.15.0-69.78", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-69-lowlatency", ver: "4.15.0-69.78", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws", ver: "4.15.0.1054.55", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws-lts-18.04", ver: "4.15.0.1054.55", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.15.0.1048.51", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke-4.15", ver: "4.15.0.1048.51", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-kvm", ver: "4.15.0.1050.50", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oem", ver: "4.15.0.1063.67", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oracle", ver: "4.15.0.1029.34", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oracle-lts-18.04", ver: "4.15.0.1029.34", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-e500mc", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc-smp", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-emb", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-powerpc64-smp", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual", ver: "4.15.0.69.71", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1029-oracle", ver: "4.15.0-1029.32~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1049-gcp", ver: "4.15.0-1049.52", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1054-aws", ver: "4.15.0-1054.56~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-1063-azure", ver: "4.15.0-1063.68", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-69-generic", ver: "4.15.0-69.78~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-69-generic-lpae", ver: "4.15.0-69.78~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-4.15.0-69-lowlatency", ver: "4.15.0-69.78~16.04.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-aws-hwe", ver: "4.15.0.1054.54", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-azure", ver: "4.15.0.1063.66", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gcp", ver: "4.15.0.1049.63", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-hwe-16.04", ver: "4.15.0.69.89", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-generic-lpae-hwe-16.04", ver: "4.15.0.69.89", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-gke", ver: "4.15.0.1049.63", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-lowlatency-hwe-16.04", ver: "4.15.0.69.89", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oem", ver: "4.15.0.69.89", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-oracle", ver: "4.15.0.1029.22", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "linux-image-virtual-hwe-16.04", ver: "4.15.0.69.89", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "Please", ver: "note that mitigating the TSX (CVE-2019-11135) and i915", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "firmware", ver: "updates respectively.", rls: "UBUNTU16.04 LTS" ) )){
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

