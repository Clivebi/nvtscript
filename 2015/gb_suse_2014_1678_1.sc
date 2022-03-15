if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850682" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-09-18 10:38:58 +0200 (Fri, 18 Sep 2015)" );
	script_cve_id( "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-8133", "CVE-2014-9090", "CVE-2014-9322" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for Linux (openSUSE-SU-2014:1678-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The openSUSE 13.2 kernel was updated to version 3.16.7.

  These security issues were fixed:

  - CVE-2014-9322: A local privilege escalation in the x86_64 32bit
  compatibility signal handling was fixed, which could be used by local
  attackers to crash the machine or execute code. (bnc#910251)

  - CVE-2014-9090: The do_double_fault function in arch/x86/kernel/traps.c
  in the Linux kernel did not properly handle faults associated with the
  Stack Segment (SS) segment register, which allowed local users to cause
  a denial of service (panic) via a modify_ldt system call, as
  demonstrated by sigreturn_32 in the linux-clock-tests test suite.
  (bnc#907818)

  - CVE-2014-8133: Insufficient validation of TLS register usage could leak
  information from the kernel stack to userspace. (bnc#909077)

  - CVE-2014-3673: The SCTP implementation in the Linux kernel through
  3.17.2 allowed remote attackers to cause a denial of service (system
  crash) via a malformed ASCONF chunk, related to net/sctp/sm_make_chunk.c
  and net/sctp/sm_statefuns.c (bnc#902346, bnc#902349).

  - CVE-2014-3687: The sctp_assoc_lookup_asconf_ack function in
  net/sctp/associola.c in the SCTP implementation in the Linux kernel
  through 3.17.2 allowed remote attackers to cause a denial of service
  (panic) via duplicate ASCONF chunks that triggered an incorrect uncork
  within the side-effect interpreter (bnc#902349).

  - CVE-2014-3688: The SCTP implementation in the Linux kernel before 3.17.4
  allowed remote attackers to cause a denial of service (memory
  consumption) by triggering a large number of chunks in an association's
  output queue, as demonstrated by ASCONF probes, related to
  net/sctp/inqueue.c and net/sctp/sm_statefuns.c (bnc#902351).

  - CVE-2014-7826: kernel/trace/trace_syscalls.c in the Linux kernel through
  3.17.2 did not properly handle private syscall numbers during use of the
  ftrace subsystem, which allowed local users to gain privileges or cause
  a denial of service (invalid pointer dereference) via a crafted
  application (bnc#904013).

  - CVE-2014-7841: The sctp_process_param function in
  net/sctp/sm_make_chunk.c in the SCTP implementation in the Linux kernel
  before 3.17.4, when ASCONF is used, allowed remote attackers to cause a
  denial of service (NULL pointer dereference and system crash) via a
  malformed INIT chunk (bnc#905100).

  These non-security issues were fixed:

  - ahci: Check and set 64-bit DMA mask for platform AHCI driver
  (bnc#902632).

  - ahci/xgene: Remove logic to set 64-bit DMA mask (bnc#902632).

  - ahci_xgene: Skip the PHY and clock initialization if already configured
 ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "Linux on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2014:1678-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2", rpm: "kernel-ec2~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base", rpm: "kernel-ec2-base~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-devel", rpm: "kernel-ec2-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build", rpm: "kernel-obs-build~3.16.7~7.3", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-build-debugsource", rpm: "kernel-obs-build-debugsource~3.16.7~7.3", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-qa", rpm: "kernel-obs-qa~3.16.7~7.2", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-obs-qa-xen", rpm: "kernel-obs-qa-xen~3.16.7~7.2", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug", rpm: "kernel-debug~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-base", rpm: "kernel-debug-base~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-base-debuginfo", rpm: "kernel-debug-base-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debuginfo", rpm: "kernel-debug-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-debugsource", rpm: "kernel-debug-debugsource~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel", rpm: "kernel-debug-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-debug-devel-debuginfo", rpm: "kernel-debug-devel-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-desktop", rpm: "kernel-desktop~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-desktop-base", rpm: "kernel-desktop-base~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-desktop-base-debuginfo", rpm: "kernel-desktop-base-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-desktop-debuginfo", rpm: "kernel-desktop-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-desktop-debugsource", rpm: "kernel-desktop-debugsource~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-desktop-devel", rpm: "kernel-desktop-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-base-debuginfo", rpm: "kernel-ec2-base-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debuginfo", rpm: "kernel-ec2-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-ec2-debugsource", rpm: "kernel-ec2-debugsource~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla", rpm: "kernel-vanilla~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debuginfo", rpm: "kernel-vanilla-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-debugsource", rpm: "kernel-vanilla-debugsource~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-vanilla-devel", rpm: "kernel-vanilla-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen", rpm: "kernel-xen~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base", rpm: "kernel-xen-base~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-base-debuginfo", rpm: "kernel-xen-base-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debuginfo", rpm: "kernel-xen-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-debugsource", rpm: "kernel-xen-debugsource~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-xen-devel", rpm: "kernel-xen-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-docs", rpm: "kernel-docs~3.16.7~7.2", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-vanilla", rpm: "kernel-source-vanilla~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae", rpm: "kernel-pae~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base", rpm: "kernel-pae-base~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-base-debuginfo", rpm: "kernel-pae-base-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-debuginfo", rpm: "kernel-pae-debuginfo~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-debugsource", rpm: "kernel-pae-debugsource~3.16.7~7.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-pae-devel", rpm: "kernel-pae-devel~3.16.7~7.1", rls: "openSUSE13.2" ) )){
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

