if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.3207.1" );
	script_cve_id( "CVE-2021-34556", "CVE-2021-35477", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3656", "CVE-2021-3679", "CVE-2021-3732", "CVE-2021-3739", "CVE-2021-3743", "CVE-2021-3753", "CVE-2021-3759", "CVE-2021-38160", "CVE-2021-38198", "CVE-2021-38204", "CVE-2021-38205", "CVE-2021-38207" );
	script_tag( name: "creation_date", value: "2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)" );
	script_version( "2021-09-24T07:56:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 07:56:06 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-14 16:16:00 +0000 (Sat, 14 Aug 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:3207-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:3207-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20213207-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3207-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-3759: Unaccounted ipc objects in Linux kernel could have lead
 to breaking memcg limits and DoS attacks (bsc#1190115).

CVE-2021-38160: Data corruption or loss could be triggered by an
 untrusted device that supplies a buf->len value exceeding the buffer
 size in drivers/char/virtio_console.c (bsc#1190117)

CVE-2021-3640: Fixed a Use-After-Free vulnerability in function
 sco_sock_sendmsg() in the bluetooth stack (bsc#1188172).

CVE-2021-3753: Fixed race out-of-bounds in virtual terminal handling
 (bsc#1190025).

CVE-2021-3743: Fixed OOB Read in qrtr_endpoint_post (bsc#1189883).

CVE-2021-3739: Fixed a NULL pointer dereference when deleting device by
 invalid id (bsc#1189832 ).

CVE-2021-3732: Mounting overlayfs inside an unprivileged user namespace
 can reveal files (bsc#1189706).

CVE-2021-3653: Missing validation of the `int_ctl` VMCB field and allows
 a malicious L1 guest to enable AVIC support for the L2 guest.
 (bsc#1189399).

CVE-2021-3656: Missing validation of the `virt_ext` VMCB field and
 allows a malicious L1 guest to disable both VMLOAD/VMSAVE intercepts and
 VLS for the L2 guest (bsc#1189400).

CVE-2021-38198: arch/x86/kvm/mmu/paging_tmpl.h incorrectly computes the
 access permissions of a shadow page, leading to a missing guest
 protection page fault (bnc#1189262).

CVE-2021-38207: drivers/net/ethernet/xilinx/ll_temac_main.c allowed
 remote attackers to cause a denial of service (buffer overflow and
 lockup) by sending heavy network traffic for about ten minutes
 (bnc#1189298).

CVE-2021-38205: drivers/net/ethernet/xilinx/xilinx_emaclite.c made it
 easier for attackers to defeat an ASLR protection mechanism because it
 prints a kernel pointer (i.e., the real IOMEM pointer) (bnc#1189292).

CVE-2021-38204: drivers/usb/host/max3421-hcd.c allowed physically
 proximate attackers to cause a denial of service (use-after-free and
 panic) by removing a MAX-3421 USB device in certain situations
 (bnc#1189291).

CVE-2021-3679: A lack of CPU resource in tracing module functionality
 was found in the way user uses trace ring buffer in a specific way. Only
 privileged local users (with CAP_SYS_ADMIN capability) could use this
 flaw to starve the resources causing denial of service (bnc#1189057).

CVE-2021-34556: Fixed side-channel attack via a Speculative Store Bypass
 via unprivileged BPF program that could have obtain sensitive
 information from kernel memory (bsc#1188983).

CVE-2021-35477: Fixed BPF stack frame pointer which could have been
 abused to disclose content of arbitrary kernel memory (bsc#1188985).


The following non-security bugs were fixed:

ACPI: NFIT: Fix support for virtual SPA ranges (git-fixes).

ACPI: processor: Clean up acpi_processor_evaluate_cst() (bsc#1175543)

ACPI: processor: Export ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Live Patching 15-SP2, SUSE Linux Enterprise Workstation Extension 15-SP2, SUSE MicroOS 5.0." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~5.3.18~24.83.2.9.38.3", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~5.3.18~24.83.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~5.3.18~24.83.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt", rpm: "kernel-preempt~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-debuginfo", rpm: "kernel-preempt-debuginfo~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-debugsource", rpm: "kernel-preempt-debugsource~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-devel", rpm: "kernel-preempt-devel~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-preempt-devel-debuginfo", rpm: "kernel-preempt-devel-debuginfo~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~5.3.18~24.83.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~5.3.18~24.83.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default", rpm: "reiserfs-kmp-default~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default-debuginfo", rpm: "reiserfs-kmp-default-debuginfo~5.3.18~24.83.2", rls: "SLES15.0SP2" ) )){
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

