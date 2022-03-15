if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3084.1" );
	script_cve_id( "CVE-2018-10853", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-10902", "CVE-2018-10938", "CVE-2018-10940", "CVE-2018-12896", "CVE-2018-13093", "CVE-2018-13094", "CVE-2018-13095", "CVE-2018-14617", "CVE-2018-14678", "CVE-2018-15572", "CVE-2018-15594", "CVE-2018-16276", "CVE-2018-16658", "CVE-2018-17182", "CVE-2018-6554", "CVE-2018-6555", "CVE-2018-7480", "CVE-2018-7757", "CVE-2018-9363" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3084-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3084-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183084-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:3084-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive various security and bugfixes.
CVE-2018-10853: A flaw was found in the way the KVM hypervisor emulated
 instructions such as sgdt/sidt/fxsave/fxrstor. It did not check current
 privilege(CPL) level while emulating unprivileged instructions. An
 unprivileged guest user/process could use this flaw to potentially
 escalate privileges inside guest (bnc#1097104).

CVE-2018-10876: A flaw was found in Linux kernel in the ext4 filesystem
 code. A use-after-free is possible in ext4_ext_remove_space() function
 when mounting and operating a crafted ext4 image. (bnc#1099811)

CVE-2018-10877: Linux kernel ext4 filesystem is vulnerable to an
 out-of-bound access in the ext4_ext_drop_refs() function when operating
 on a crafted ext4 filesystem image. (bnc#1099846)

CVE-2018-10878: A flaw was found in the Linux kernel's ext4 filesystem.
 A local user can cause an out-of-bounds write and a denial of service or
 unspecified other impact is possible by mounting and operating a crafted
 ext4 filesystem image. (bnc#1099813)

CVE-2018-10879: A flaw was found in the Linux kernel's ext4 filesystem.
 A local user can cause a use-after-free in ext4_xattr_set_entry function
 and a denial of service or unspecified other impact may occur by
 renaming a file in a crafted ext4 filesystem image. (bnc#1099844)

CVE-2018-10880: Linux kernel is vulnerable to a stack-out-of-bounds
 write in the ext4 filesystem code when mounting and writing to a crafted
 ext4 image in ext4_update_inline_data(). An attacker could use this to
 cause a system crash and a denial of service. (bnc#1099845)

CVE-2018-10881: A flaw was found in the Linux kernel's ext4 filesystem.
 A local user can cause an out-of-bound access in ext4_get_group_info
 function, a denial of service, and a system crash by mounting and
 operating on a crafted ext4 filesystem image. (bnc#1099864)

CVE-2018-10882: A flaw was found in the Linux kernel's ext4 filesystem.
 A local user can cause an out-of-bound write in fs/jbd2/transaction.c
 code, a denial of service, and a system crash by unmounting a crafted
 ext4 filesystem image. (bnc#1099849)

CVE-2018-10883: A flaw was found in the Linux kernel's ext4 filesystem.
 A local user can cause an out-of-bounds write in
 jbd2_journal_dirty_metadata(), a denial of service, and a system crash
 by mounting and operating on a crafted ext4 filesystem image.
 (bnc#1099863)

CVE-2018-10902: It was found that the raw midi kernel driver did not
 protect against concurrent access which leads to a double realloc
 (double free) in snd_rawmidi_input_params() and
 snd_rawmidi_output_status() which are part of snd_rawmidi_ioctl()
 handler in rawmidi.c file. A malicious local attacker could possibly use
 this for privilege escalation (bnc#1105322).

CVE-2018-10938: A crafted network packet sent remotely by an attacker
 may force the kernel to enter an ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Enterprise Storage 4, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.121~92.95.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_95-default", rpm: "kgraft-patch-4_4_121-92_95-default~1~3.4.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules", rpm: "lttng-modules~2.7.1~9.6.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-debugsource", rpm: "lttng-modules-debugsource~2.7.1~9.6.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-kmp-default", rpm: "lttng-modules-kmp-default~2.7.1_k4.4.121_92.95~9.6.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "lttng-modules-kmp-default-debuginfo", rpm: "lttng-modules-kmp-default-debuginfo~2.7.1_k4.4.121_92.95~9.6.1", rls: "SLES12.0SP2" ) )){
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

