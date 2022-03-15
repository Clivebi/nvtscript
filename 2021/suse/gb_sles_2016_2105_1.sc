if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2105.1" );
	script_cve_id( "CVE-2014-9904", "CVE-2015-7833", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8845", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-3672", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4805", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5244", "CVE-2016-5828", "CVE-2016-5829" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2105-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2105-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162105-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2105-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.62 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2014-9904: The snd_compress_check_input function in
 sound/core/compress_offload.c in the ALSA subsystem in the Linux kernel
 did not properly check for an integer overflow, which allowed local
 users to cause a denial of service (insufficient memory allocation) or
 possibly have unspecified other impact via a crafted
 SNDRV_COMPRESS_SET_PARAMS ioctl call (bnc#986811).
- CVE-2015-7833: The usbvision driver in the Linux kernel allowed
 physically proximate attackers to cause a denial of service (panic) via
 a nonzero bInterfaceNumber value in a USB device descriptor (bnc#950998).
- CVE-2015-8551: The PCI backend driver in Xen, when running on an x86
 system and using Linux as the driver domain, allowed local guest
 administrators to hit BUG conditions and cause a denial of service (NULL
 pointer dereference and host OS crash) by leveraging a system with
 access to a passed-through MSI or MSI-X capable physical PCI device and
 a crafted sequence of XEN_PCI_OP_* operations, aka 'Linux pciback
 missing sanity checks (bnc#957990).
- CVE-2015-8552: The PCI backend driver in Xen, when running on an x86
 system and using Linux as the driver domain, allowed local guest
 administrators to generate a continuous stream of WARN messages and
 cause a denial of service (disk consumption) by leveraging a system with
 access to a passed-through MSI or MSI-X capable physical PCI device and
 XEN_PCI_OP_enable_msi operations, aka 'Linux pciback missing sanity
 checks (bnc#957990).
- CVE-2015-8845: The tm_reclaim_thread function in
 arch/powerpc/kernel/process.c in the Linux kernel on powerpc platforms
 did not ensure that TM suspend mode exists before proceeding with a
 tm_reclaim call, which allowed local users to cause a denial of service
 (TM Bad Thing exception and panic) via a crafted application
 (bnc#975533).
- CVE-2016-0758: Integer overflow in lib/asn1_decoder.c in the Linux
 kernel allowed local users to gain privileges via crafted ASN.1 data
 (bnc#979867).
- CVE-2016-1583: The ecryptfs_privileged_open function in
 fs/ecryptfs/kthread.c in the Linux kernel allowed local users to gain
 privileges or cause a denial of service (stack memory consumption) via
 vectors involving crafted mmap calls for /proc pathnames, leading to
 recursive pagefault handling (bsc#983143).
- CVE-2016-2053: The asn1_ber_decoder function in lib/asn1_decoder.c in
 the Linux kernel allowed attackers to cause a denial of service (panic)
 via an ASN.1 BER file that lacks a public key, leading to mishandling by
 the public_key_verify_signature function in
 crypto/asymmetric_keys/public_key.c (bnc#963762).
- CVE-2016-3672: The arch_pick_mmap_layout function in arch/x86/mm/mmap.c
 in the Linux kernel did not properly randomize the legacy base address,
 which made ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Workstation Extension 12-SP1." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.12.62~60.62.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.12.62~60.62.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.12.62~60.62.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.12.62~60.62.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra", rpm: "kernel-ec2-extra~3.12.62~60.62.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra-debuginfo", rpm: "kernel-ec2-extra-debuginfo~3.12.62~60.62.1", rls: "SLES12.0" ) )){
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.62~60.62.1", rls: "SLES12.0SP1" ) )){
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

