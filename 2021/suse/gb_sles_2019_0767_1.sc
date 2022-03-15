if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0767.1" );
	script_cve_id( "CVE-2018-20669", "CVE-2019-2024", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-3819", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-7308", "CVE-2019-8912", "CVE-2019-8980", "CVE-2019-9213" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0767-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0767-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190767-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:0767-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise Server 12 SP4 Azure kernel was updated to fix various issues.

The following security bugs were fixed:
CVE-2019-2024: A use-after-free when disconnecting a source was fixed
 which could lead to crashes. bnc#1129179).

CVE-2019-9213: expand_downwards in mm/mmap.c lacked a check for the mmap
 minimum address, which made it easier for attackers to exploit kernel
 NULL pointer dereferences on non-SMAP platforms. This is related to a
 capability check for the wrong task (bnc#1128166 1128378 1129016).

CVE-2019-8980: A memory leak in the kernel_read_file function in
 fs/exec.c allowed attackers to cause a denial of service (memory
 consumption) by triggering vfs_read failures (bnc#1126209).

CVE-2019-3819: A flaw was found in the function hid_debug_events_read()
 in drivers/hid/hid-debug.c file which may enter an infinite loop with
 certain parameters passed from a userspace. A local privileged user
 ('root') can cause a system lock up and a denial of service.
 (bnc#1123161).

CVE-2019-8912: af_alg_release() in crypto/af_alg.c neglected to set a
 NULL value for a certain structure member, which led to a use-after-free
 in sockfs_setattr (bnc#1125907 1126284).

CVE-2019-7308: kernel/bpf/verifier.c performed undesirable out-of-bounds
 speculation on pointer arithmetic in various cases, including cases of
 different branches with different state or limits to sanitize, leading
 to side-channel attacks (bnc#1124055).

CVE-2019-3459, CVE-2019-3460: The Bluetooth stack suffered from two
 remote information leak vulnerabilities in the code that handles
 incoming L2cap configuration packets (bsc#1120758).

CVE-2019-7221: Fixed a use-after-free vulnerability in the KVM
 hypervisor related to the emulation of a preemption timer, allowing an
 guest user/process to crash the host kernel. (bsc#1124732).

CVE-2019-7222: Fixed an information leakage in the KVM hypervisor
 related to handling page fault exceptions, which allowed a guest
 user/process to use this flaw to leak the host's stack memory contents
 to a guest (bsc#1124735).

CVE-2019-6974: kvm_ioctl_create_device in virt/kvm/kvm_main.c mishandled
 reference counting because of a race condition, leading to a
 use-after-free (bnc#1124728).

CVE-2018-20669: An issue where a provided address with access_ok() is
 not checked was discovered in i915_gem_execbuffer2_ioctl in
 drivers/gpu/drm/i915/i915_gem_execbuffer.c where a local attacker can
 craft a malicious IOCTL function call to overwrite arbitrary kernel
 memory, resulting in a Denial of Service or privilege escalation
 (bnc#1122971).

The following non-security bugs were fixed:
6lowpan: iphc: reset mac_header after decompress to fix panic
 (bsc#1051510).

9p: clear dangling pointers in p9stat_free (bsc#1051510).

9p locks: fix glock.client_id leak in do_lock (bsc#1051510).

9p/net: fix memory leak in p9_client_create (bsc#1051510).

9p/net: put a lower ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~6.9.1", rls: "SLES12.0SP4" ) )){
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

