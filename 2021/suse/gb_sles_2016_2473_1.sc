if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2473.1" );
	script_cve_id( "CVE-2016-6258", "CVE-2016-6259", "CVE-2016-6833", "CVE-2016-6834", "CVE-2016-6835", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2473-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2473-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162473-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:2473-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes several issues.
These security issues were fixed:
- CVE-2016-7092: The get_page_from_l3e function in arch/x86/mm.c in Xen
 allowed local 32-bit PV guest OS administrators to gain host OS
 privileges via vectors related to L3 recursive pagetables (bsc#995785).
- CVE-2016-7093: Xen allowed local HVM guest OS administrators to
 overwrite hypervisor memory and consequently gain host OS privileges by
 leveraging mishandling of instruction pointer truncation during
 emulation (bsc#995789).
- CVE-2016-7094: Buffer overflow in Xen allowed local x86 HVM guest OS
 administrators on guests running with shadow paging to cause a denial of
 service via a pagetable update (bsc#995792).
- CVE-2016-6836: Information leakage in vmxnet3_complete_packet
 (bsc#994761).
- CVE-2016-6888: Integer overflow in packet initialisation in VMXNET3
 device driver. Aprivileged user inside guest c... (bsc#994772).
- CVE-2016-6833: Use after free while writing (bsc#994775).
- CVE-2016-6835: Buffer overflow in vmxnet_tx_pkt_parse_headers() in
 vmxnet3 deviceemulation. (bsc#994625).
- CVE-2016-6834: An infinite loop during packet fragmentation (bsc#994421).
- CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in Xen allowed
 local 32-bit PV guest OS administrators to gain host OS privileges by
 leveraging fast-paths for updating pagetable entries (bsc#988675).
- CVE-2016-6259: Xen did not implement Supervisor Mode Access Prevention
 (SMAP) whitelisting in 32-bit exception and event delivery, which
 allowed local 32-bit PV guest OS kernels to cause a denial of service
 (hypervisor and VM crash) by triggering a safety check (bsc#988676).
These non-security issues were fixed:
- bsc#991934: Hypervisor crash in csched_acct
- bsc#992224: During boot of Xen Hypervisor, failed to get contiguous
 memory for DMA
- bsc#955104: Virsh reports error 'one or more references were leaked
 after disconnect from hypervisor' when 'virsh save' failed due to 'no
 response from client after 6 keepalive messages'
- bsc#959552: Migration of HVM guest leads into libvirt segmentation fault
- bsc#993665: Migration of xen guests finishes in: One or more references
 were leaked after disconnect from the hypervisor
- bsc#959330: Guest migrations using virsh results in error 'Internal
 error: received hangup / error event on socket'
- bsc#990500: VM virsh migration fails with keepalive error:
 ':virKeepAliveTimerInternal:143 : No response from client'
- bsc#953518: Unplug also SCSI disks in qemu-xen-traditional for upstream
 unplug protocol
- bsc#953518: xen_platform: unplug also SCSI disks in qemu-xen
- bsc#971949: xl: Support (by ignoring) xl migrate --live. xl migrations
 are always live
- bsc#970135: New virtualization project clock test randomly fails on Xen
- bsc#990970: Add PMU support for Intel E7-8867 v4 (fam=6, model=79)" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.5.3_10_k3.12.62_60.62~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default-debuginfo", rpm: "xen-kmp-default-debuginfo~4.5.3_10_k3.12.62_60.62~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.5.3_10~20.1", rls: "SLES12.0SP1" ) )){
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

