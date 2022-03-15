if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2374.1" );
	script_cve_id( "CVE-2017-18344", "CVE-2018-14734", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-5390", "CVE-2018-5391" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-23 17:29:00 +0000 (Tue, 23 Apr 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2374-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2374-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182374-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2374-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 Azure kernel was updated to 4.4.143 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-3620: Local attackers on baremetal systems could use
 speculative code patterns on hyperthreaded processors to read data
 present in the L1 Datacache used by other hyperthreads on the same CPU
 core, potentially leaking sensitive data. (bnc#1087081).
- CVE-2018-3646: Local attackers in virtualized guest systems could use
 speculative code patterns on hyperthreaded processors to read data
 present in the L1 Datacache used by other hyperthreads on the same CPU
 core, potentially leaking sensitive data, even from other virtual
 machines or the host system. (bnc#1089343).
- CVE-2018-5391: A flaw in the IP packet reassembly could be used by
 remote attackers to consume CPU time (bnc#1103097).
- CVE-2018-5390: Linux kernel versions 4.9+ can be forced to make very
 expensive calls to tcp_collapse_ofo_queue() and tcp_prune_ofo_queue()
 for every incoming packet which can lead to a denial of service
 (bnc#1102340).
- CVE-2018-14734: drivers/infiniband/core/ucma.c allowed
 ucma_leave_multicast to access a certain data structure after a cleanup
 step in ucma_process_join, which allowed attackers to cause a denial of
 service (use-after-free) (bnc#1103119).
- CVE-2017-18344: The timer_create syscall implementation in
 kernel/time/posix-timers.c didn't properly validate the
 sigevent->sigev_notify field, which leads to out-of-bounds access in the
 show_timer function (called when /proc/$PID/timers is read). This
 allowed userspace applications to read arbitrary kernel memory (on a
 kernel built with CONFIG_POSIX_TIMERS and CONFIG_CHECKPOINT_RESTORE)
 (bnc#1102851 1103580).
The following non-security bugs were fixed:
- 1wire: family module autoload fails because of upper/lower case mismatch
 (bnc#1012382).
- Add support for 5,25,50, and 100G to 802.3ad bonding driver (bsc#1096978)
- ahci: Disable LPM on Lenovo 50 series laptops with a too old BIOS
 (bnc#1012382).
- alsa: hda - Fix pincfg at resume on Lenovo T470 dock (bsc#1099810).
- alsa: hda - Handle kzalloc() failure in snd_hda_attach_pcm_stream()
 (bnc#1012382).
- alsa: hda/realtek - set PINCFG_HEADSET_MIC to parse_flags (bsc#1099810).
- arm64: do not open code page table entry creation (bsc#1102197).
- arm64: kpti: Use early_param for kpti= command-line option (bsc#1102188).
- arm64: Make sure permission updates happen for pmd/pud (bsc#1102197).
- arm: 8764/1: kgdb: fix NUMREGBYTES so that gdb_regs[] is the correct
 size (bnc#1012382).
- arm: dts: imx6q: Use correct SDMA script for SPI5 core (bnc#1012382).
- ASoC: cirrus: i2s: Fix LRCLK configuration (bnc#1012382).
- ASoC: cirrus: i2s: Fix {TX<pipe>RX}LinCtrlData setup (bnc#1012382).
- ASoC: dapm: delete dapm_kcontrol_data paths list before freeing it
 (bnc#1012382).
- ath10k: fix rfc1042 header retrieval in QCA4019 with ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.4.143~4.13.1", rls: "SLES12.0SP3" ) )){
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

