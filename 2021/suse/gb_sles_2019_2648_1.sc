if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2648.1" );
	script_cve_id( "CVE-2017-18551", "CVE-2017-18595", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-10207", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15030", "CVE-2019-15031", "CVE-2019-15090", "CVE-2019-15098", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15214", "CVE-2019-15215", "CVE-2019-15216", "CVE-2019-15217", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15222", "CVE-2019-15239", "CVE-2019-15290", "CVE-2019-15291", "CVE-2019-15292", "CVE-2019-15538", "CVE-2019-15666", "CVE-2019-15902", "CVE-2019-15917", "CVE-2019-15919", "CVE-2019-15920", "CVE-2019-15921", "CVE-2019-15924", "CVE-2019-15926", "CVE-2019-15927", "CVE-2019-9456", "CVE-2019-9506" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-03 00:15:00 +0000 (Tue, 03 Sep 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2648-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2648-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192648-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2648-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP4 for Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2019-15291: There was a NULL pointer dereference caused by a
 malicious USB device in the flexcop_usb_probe function in the
 drivers/media/usb/b2c2/flexcop-usb.c driver (bnc#1146540).

CVE-2019-14821: An out-of-bounds access issue was found in the way Linux
 kernel's KVM hypervisor implements the coalesced MMIO write operation.
 It operates on an MMIO ring buffer 'struct kvm_coalesced_mmio' object,
 wherein write indices 'ring->first' and 'ring->last' value could be
 supplied by a host user-space process. An unprivileged host user or
 process with access to '/dev/kvm' device could use this flaw to crash
 the host kernel, resulting in a denial of service or potentially
 escalating privileges on the system (bnc#1151350).

CVE-2017-18595: A double free may be caused by the function
 allocate_trace_buffer in the file kernel/trace/trace.c (bnc#1149555).

CVE-2019-9506: The Bluetooth BR/EDR specification up to and including
 version 5.1 permitted sufficiently low encryption key length and did not
 prevent an attacker from influencing the key length negotiation. This
 allowed practical brute-force attacks (aka 'KNOB') that could decrypt
 traffic and injected arbitrary ciphertext without the victim noticing
 (bnc#1137865 bnc#1146042).

CVE-2019-14835: A buffer overflow flaw was found in the way Linux
 kernel's vhost functionality that translates virtqueue buffers to IOVs,
 logged the buffer descriptors during migration. A privileged guest user
 able to pass descriptors with invalid length to the host when migration
 is underway, could have used this flaw to increase their privileges on
 the host (bnc#1150112).

CVE-2019-15216: There was a NULL pointer dereference caused by a
 malicious USB device in the drivers/usb/misc/yurex.c driver
 (bnc#1146361).

CVE-2019-15924: fm10k_init_module in
 drivers/net/ethernet/intel/fm10k/fm10k_main.c had a NULL pointer
 dereference because there was no -ENOMEM upon an alloc_workqueue failure
 (bnc#1149612).

CVE-2019-9456: In the Pixel C USB monitor driver there was a possible
 OOB write due to a missing bounds check. This could have led to local
 escalation of privilege with System execution privileges needed. User
 interaction is not needed for exploitation (bnc#1150025).

CVE-2019-15031: In the Linux kernel on the powerpc platform, a local
 user could have read vector registers of other users' processes via an
 interrupt. To exploit the vulnerability, a local user starts a
 transaction (via the hardware transactional memory instruction tbegin)
 and then accesses vector registers. At some point, the vector registers
 will be corrupted with the values from a different local Linux process,
 because MSR_TM_ACTIVE was misused in arch/powerpc/kernel/process.c
 (bnc#1149713).

CVE-2019-15030: In the ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~6.26.1", rls: "SLES12.0SP4" ) )){
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

