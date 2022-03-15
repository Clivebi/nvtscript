if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2869.1" );
	script_cve_id( "CVE-2017-1000252", "CVE-2017-10810", "CVE-2017-11472", "CVE-2017-11473", "CVE-2017-12134", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-14106", "CVE-2017-14489", "CVE-2017-15649", "CVE-2017-6346", "CVE-2017-7518", "CVE-2017-7541", "CVE-2017-7542", "CVE-2017-8831" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2869-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2869-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172869-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2017:2869-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.90 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2017-1000252: The KVM subsystem in the Linux kernel allowed guest OS
 users to cause a denial of service (assertion failure, and hypervisor
 hang or crash) via an out-of bounds guest_irq value, related to
 arch/x86/kvm/vmx.c and virt/kvm/eventfd.c (bnc#1058038).
- CVE-2017-10810: Memory leak in the virtio_gpu_object_create function in
 drivers/gpu/drm/virtio/virtgpu_object.c in the Linux kernel allowed
 attackers to cause a denial of service (memory consumption) by
 triggering object-initialization failures (bnc#1047277).
- CVE-2017-11472: The acpi_ns_terminate() function in
 drivers/acpi/acpica/nsutils.c in the Linux kernel did not flush the
 operand cache and causes a kernel stack dump, which allowed local users
 to obtain sensitive information from kernel memory and bypass the KASLR
 protection mechanism (in the kernel through 4.9) via a crafted ACPI
 table (bnc#1049580).
- CVE-2017-11473: Buffer overflow in the mp_override_legacy_irq() function
 in arch/x86/kernel/acpi/boot.c in the Linux kernel allowed local users
 to gain privileges via a crafted ACPI table (bnc#1049603).
- CVE-2017-12134: The xen_biovec_phys_mergeable function in
 drivers/xen/biomerge.c in Xen might allow local OS guest users to
 corrupt block device data streams and consequently obtain sensitive
 memory information, cause a denial of service, or gain host OS
 privileges by leveraging incorrect block IO merge-ability calculation
 (bnc#1051790 bnc#1053919).
- CVE-2017-12153: A security flaw was discovered in the
 nl80211_set_rekey_data() function in net/wireless/nl80211.c in the Linux
 kernel This function did not check whether the required attributes are
 present in a Netlink request. This request can be issued by a user with
 the CAP_NET_ADMIN capability and may result in a NULL pointer
 dereference and system crash (bnc#1058410).
- CVE-2017-12154: The prepare_vmcs02 function in arch/x86/kvm/vmx.c in the
 Linux kernel did not ensure that the 'CR8-load exiting' and 'CR8-store
 exiting' L0 vmcs02 controls exist in cases where L1 omits the 'use TPR
 shadow' vmcs12 control, which allowed KVM L2 guest OS users to obtain
 read and write access to the hardware CR8 register (bnc#1058507).
- CVE-2017-13080: Wi-Fi Protected Access (WPA and WPA2) allowed
 reinstallation of the Group Temporal Key (GTK) during the group key
 handshake, allowing an attacker within radio range to replay frames from
 access points to clients (bnc#1063667).
- CVE-2017-14051: An integer overflow in the
 qla2x00_sysfs_write_optrom_ctl function in
 drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel allowed local users
 to cause a denial of service (memory corruption and system crash) by
 leveraging root access (bnc#1056588).
- CVE-2017-14106: The tcp_disconnect function in ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Container as a Service Platform ALL, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.90~92.45.1", rls: "SLES12.0SP2" ) )){
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

