if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.2194.1" );
	script_cve_id( "CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5283", "CVE-2015-5307", "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104", "CVE-2015-8215" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-17 01:29:00 +0000 (Wed, 17 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:2194-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:2194-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20152194-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2015:2194-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 kernel was updated to 3.12.51 to receive various security and bugfixes.
Following security bugs were fixed:
- CVE-2015-7799: The slhc_init function in drivers/net/slip/slhc.c in the
 Linux kernel did not ensure that certain slot numbers were valid, which
 allowed local users to cause a denial of service (NULL pointer
 dereference and system crash) via a crafted PPPIOCSMAXCID ioctl call
 (bnc#949936).
- CVE-2015-5283: The sctp_init function in net/sctp/protocol.c in the
 Linux kernel had an incorrect sequence of protocol-initialization steps,
 which allowed local users to cause a denial of service (panic or memory
 corruption) by creating SCTP sockets before all of the steps have
 finished (bnc#947155).
- CVE-2015-2925: The prepend_path function in fs/dcache.c in the Linux
 kernel did not properly handle rename actions inside a bind mount, which
 allowed local users to bypass an intended container protection mechanism
 by renaming a directory, related to a 'double-chroot attack (bnc#926238).
- CVE-2015-8104: The KVM subsystem in the Linux kernel allowed guest OS
 users to cause a denial of service (host OS panic or hang) by triggering
 many #DB (aka Debug) exceptions, related to svm.c (bnc#954404).
- CVE-2015-5307: The KVM subsystem in the Linux kernel allowed guest OS
 users to cause a denial of service (host OS panic or hang) by triggering
 many #AC (aka Alignment Check) exceptions, related to svm.c and vmx.c
 (bnc#953527).
- CVE-2015-7990: RDS: There was no verification that an underlying
 transport exists when creating a connection, causing usage of a NULL
 pointer (bsc#952384).
- CVE-2015-7872: The key_gc_unused_keys function in security/keys/gc.c in
 the Linux kernel allowed local users to cause a denial of service (OOPS)
 via crafted keyctl commands (bnc#951440).
- CVE-2015-0272: Missing checks allowed remote attackers to cause a denial
 of service (IPv6 traffic disruption) via a crafted MTU value in an IPv6
 Router Advertisement (RA) message, a different vulnerability than
 CVE-2015-8215 (bnc#944296).
The following non-security bugs were fixed:
- ALSA: hda - Disable 64bit address for Creative HDA controllers
 (bnc#814440).
- Add PCI IDs of Intel Sunrise Point-H SATA Controller S232/236
 (bsc#953796).
- Btrfs: fix file corruption and data loss after cloning inline extents
 (bnc#956053).
- Btrfs: fix truncation of compressed and inlined extents (bnc#956053).
- Disable some ppc64le netfilter modules to restore the kabi (bsc#951546)
- Fix regression in NFSRDMA server (bsc#951110).
- KEYS: Fix race between key destruction and finding a keyring by name
 (bsc#951440).
- KVM: x86: call irq notifiers with directed EOI (bsc#950862).
- NVMe: Add shutdown timeout as module parameter (bnc#936076).
- NVMe: Mismatched host/device page size support (bsc#935961).
- PCI: Drop 'setting latency timer' messages (bsc#956047).
- SCSI: Fix hard lockup in ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Live Patching 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12, SUSE Linux Enterprise Workstation Extension 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra", rpm: "kernel-ec2-extra~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-extra-debuginfo", rpm: "kernel-ec2-extra-debuginfo~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.51~52.31.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.51~52.31.1", rls: "SLES12.0" ) )){
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

