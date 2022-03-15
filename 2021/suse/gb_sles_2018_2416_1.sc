if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2416.1" );
	script_cve_id( "CVE-2017-18344", "CVE-2018-10853", "CVE-2018-3646" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.7" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2416-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2416-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182416-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 9 for SLE 12 SP3)' package(s) announced via the SUSE-SU-2018:2416-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.4.114-94_14 fixes several issues.
The following security issues were fixed:
- CVE-2018-3646: Local attackers in virtualized guest systems could use
 speculative code patterns on hyperthreaded processors to read data
 present in the L1 Datacache used by other hyperthreads on the same CPU
 core, potentially leaking sensitive data, even from other virtual
 machines or the host system (bsc#1099306).
- CVE-2017-18344: The timer_create syscall implementation in
 kernel/time/posix-timers.c didn't properly validate the
 sigevent->sigev_notify field, which lead to out-of-bounds access in the
 show_timer function (called when /proc/$PID/timers is read). This
 allowed userspace applications to read arbitrary kernel memory (on a
 kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE)
 (bsc#1103203). before 4.14.8
- CVE-2018-10853: A flaw was found in kvm. In which certain instructions
 such as sgdt/sidt call segmented_write_std didn't propagate access
 correctly. As such, during userspace induced exception, the guest can
 incorrectly assume that the exception happened in the kernel and panic.
 (bsc#1097108)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 9 for SLE 12 SP3)' package(s) on SUSE Linux Enterprise Live Patching 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_103-92_53-default", rpm: "kgraft-patch-4_4_103-92_53-default~8~2.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_103-92_56-default", rpm: "kgraft-patch-4_4_103-92_56-default~8~2.1", rls: "SLES12.0SP2" ) )){
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

