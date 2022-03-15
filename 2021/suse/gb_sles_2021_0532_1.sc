if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0532.1" );
	script_cve_id( "CVE-2020-25639", "CVE-2020-27835", "CVE-2020-29568", "CVE-2020-29569", "CVE-2021-0342", "CVE-2021-20177", "CVE-2021-3347", "CVE-2021-3348" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-12 05:15:00 +0000 (Mon, 12 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0532-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0532-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210532-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0532-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 15 SP1 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3347: A use-after-free was discovered in the PI futexes during
 fault handling, allowing local users to execute code in the kernel
 (bnc#1181349).

CVE-2021-3348: Fixed a use-after-free in nbd_add_socket that could be
 triggered by local attackers (with access to the nbd device) via an I/O
 request at a certain point during device setup (bnc#1181504).

CVE-2021-20177: Fixed a kernel panic related to iptables string matching
 rules. A privileged user could insert a rule which could lead to denial
 of service (bnc#1180765).

CVE-2021-0342: In tun_get_user of tun.c, there is possible memory
 corruption due to a use after free. This could lead to local escalation
 of privilege with System execution privileges required. (bnc#1180812)

CVE-2020-27835: A use-after-free in the infiniband hfi1 driver was
 found, specifically in the way user calls Ioctl after open dev file and
 fork. A local user could use this flaw to crash the system (bnc#1179878).

CVE-2020-25639: Fixed a NULL pointer dereference via nouveau ioctl
 (bnc#1176846).

CVE-2020-29569: Fixed a potential privilege escalation and information
 leaks related to the PV block backend, as used by Xen (bnc#1179509).

CVE-2020-29568: Fixed a denial of service issue, related to processing
 watch events (bnc#1179508).

The following non-security bugs were fixed:

ACPI: scan: Harden acpi_device_add() against device ID overflows
 (git-fixes).

ACPI: scan: Make acpi_bus_get_device() clear return pointer on error
 (git-fixes).

ACPI: scan: add stub acpi_create_platform_device() for !CONFIG_ACPI
 (git-fixes).

ALSA: doc: Fix reference to mixart.rst (git-fixes).

ALSA: fireface: Fix integer overflow in transmit_midi_msg() (git-fixes).

ALSA: firewire-tascam: Fix integer overflow in midi_port_work()
 (git-fixes).

ALSA: hda/via: Add minimum mute flag (git-fixes).

ALSA: hda/via: Fix runtime PM for Clevo W35xSS (git-fixes).

ALSA: pcm: Clear the full allocated memory at hw_params (git-fixes).

ALSA: seq: oss: Fix missing error check in snd_seq_oss_synth_make_info()
 (git-fixes).

ASoC: Intel: haswell: Add missing pm_ops (git-fixes).

ASoC: dapm: remove widget from dirty list on free (git-fixes).

EDAC/amd64: Fix PCI component registration (bsc#1112178).

IB/mlx5: Fix DEVX support for MLX5_CMD_OP_INIT2INIT_QP command
 (bsc#1103991).

KVM: SVM: Initialize prev_ga_tag before use (bsc#1180912).

KVM: x86/mmu: Commit zap of remaining invalid pages when recovering
 lpages (bsc#1181230).

NFS4: Fix use-after-free in trace_event_raw_event_nfs4_set_lock
 (git-fixes).

NFS: nfs_igrab_and_active must first reference the superblock
 (git-fixes).

NFS: switch nfsiod to be an UNBOUND workqueue (git-fixes).

NFSv4.2: condition READDIR's mask for security label based on LSM state
 (git-fixes).

RDMA/addr: ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Availability 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Live Patching 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Workstation Extension 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel-debuginfo", rpm: "kernel-default-devel-debuginfo~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-zfcpdump-debuginfo", rpm: "kernel-zfcpdump-debuginfo~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-zfcpdump-debugsource", rpm: "kernel-zfcpdump-debugsource~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default", rpm: "reiserfs-kmp-default~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "reiserfs-kmp-default-debuginfo", rpm: "reiserfs-kmp-default-debuginfo~4.12.14~197.83.1", rls: "SLES15.0SP1" ) )){
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

