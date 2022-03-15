if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850904" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-10-16 13:54:05 +0200 (Fri, 16 Oct 2015)" );
	script_cve_id( "CVE-2015-5156", "CVE-2015-5157", "CVE-2015-5283", "CVE-2015-5697", "CVE-2015-6252", "CVE-2015-6937", "CVE-2015-7613" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for kernel-source (SUSE-SU-2015:1727-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-source'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 kernel was updated to 3.12.48-52.27 to
  receive various security and bugfixes.

  The following security bugs were fixed:

  * CVE-2015-7613: A flaw was found in the Linux kernel IPC code that could
  lead to arbitrary code execution. The ipc_addid() function initialized a
  shared object that has unset uid/gid values. Since the fields are not
  initialized, the check can falsely succeed. (bsc#948536)

  * CVE-2015-5156: When a guests KVM network devices is in a bridge
  configuration the kernel can create a situation in which packets are
  fragmented in an unexpected fashion. The GRO functionality can create a
  situation in which multiple SKB's are chained together in a single
  packets fraglist (by design). (bsc#940776)

  * CVE-2015-5157: arch/x86/entry/entry_64.S in the Linux kernel before
  4.1.6 on the x86_64 platform mishandles IRET faults in processing NMIs
  that occurred during userspace execution, which might allow local users
  to gain privileges by triggering an NMI (bsc#938706).

  * CVE-2015-6252: A flaw was found in the way the Linux kernel's vhost
  driver treated userspace provided log file descriptor when processing
  the VHOST_SET_LOG_FD ioctl command. The file descriptor was never
  released and continued to consume kernel memory. A privileged local user
  with access to the /dev/vhost-net files could use this flaw to create a
  denial-of-service attack (bsc#942367).

  * CVE-2015-5697: The get_bitmap_file function in drivers/md/md.c in the
  Linux kernel before 4.1.6 does not initialize a certain bitmap data
  structure, which allows local users to obtain sensitive information from
  kernel memory via a GET_BITMAP_FILE ioctl call. (bnc#939994)

  * CVE-2015-6937: A NULL pointer dereference flaw was found in the Reliable
  Datagram Sockets (RDS) implementation allowing a local user to cause
  system DoS. A verification was missing that the underlying transport
  exists when a connection was created. (bsc#945825)

  * CVE-2015-5283: A NULL pointer dereference flaw was found in SCTP
  implementation allowing a local user to cause system DoS. Creation of
  multiple sockets in parallel when system doesn't have SCTP module loaded
  can lead to kernel panic. (bsc#947155)

  The following non-security bugs were fixed:

  - ALSA: hda - Abort the probe without i915 binding for HSW/BDW
  (bsc#936556).

  - Btrfs: Backport subvolume mount option handling (bsc#934962)

  - Btrfs: Handle unaligned length in extent_same (bsc#937609).

  - Btrfs: advertise which crc32c implementation is being used on mount
  ( ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "kernel-source on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:1727-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(SLED12\\.0SP0|SLES12\\.0SP0)" );
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
if(release == "SLED12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra", rpm: "kernel-default-extra~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-extra-debuginfo", rpm: "kernel-default-extra-debuginfo~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.48~52.27.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.48~52.27.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.48~52.27.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.48~52.27.2", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.48~52.27.1", rls: "SLED12.0SP0" ) )){
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
if(release == "SLES12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.12.48~52.27.2", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.12.48~52.27.2", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.12.48~52.27.2", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.12.48~52.27.2", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.12.48~52.27.2", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.12.48~52.27.2", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~3.12.48~52.27.1", rls: "SLES12.0SP0" ) )){
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

