if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0098.1" );
	script_cve_id( "CVE-2018-20669", "CVE-2019-20934", "CVE-2020-0444", "CVE-2020-0465", "CVE-2020-0466", "CVE-2020-15436", "CVE-2020-27068", "CVE-2020-27777", "CVE-2020-27786", "CVE-2020-27825", "CVE-2020-29371", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-4788" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-15 18:15:00 +0000 (Tue, 15 Sep 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0098-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0098-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210098-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0098-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2018-20669: Fixed an improper check i915_gem_execbuffer2_ioctl in
 drivers/gpu/drm/i915/i915_gem_execbuffer.c (bsc#1122971).

CVE-2019-20934: Fixed a use-after-free in show_numa_stats() because NUMA
 fault statistics were inappropriately freed, aka CID-16d51a590a8c
 (bsc#1179663).

CVE-2020-0444: Fixed a bad kfree due to a logic error in
 audit_data_to_entry (bnc#1180027).

CVE-2020-0465: Fixed multiple missing bounds checks in hid-multitouch.c
 that could have led to local privilege escalation (bnc#1180029).

CVE-2020-0466: Fixed a use-after-free due to a logic error in
 do_epoll_ctl and ep_loop_check_proc of eventpoll.c (bnc#1180031).

CVE-2020-4788: Fixed an issue with IBM Power9 processors could have
 allowed a local user to obtain sensitive information from the data in
 the L1 cache under extenuating circumstances (bsc#1177666).

CVE-2020-15436: Fixed a use after free vulnerability in fs/block_dev.c
 which could have allowed local users to gain privileges or cause a
 denial of service (bsc#1179141).

CVE-2020-27068: Fixed an out-of-bounds read due to a missing bounds
 check in the nl80211_policy policy of nl80211.c (bnc#1180086).

CVE-2020-27777: Fixed a privilege escalation in the Run-Time Abstraction
 Services (RTAS) interface, affecting guests running on top of PowerVM or
 KVM hypervisors (bnc#1179107).

CVE-2020-27786: Fixed an out-of-bounds write in the MIDI implementation
 (bnc#1179601).

CVE-2020-27825: Fixed a race in the trace_open and buffer resize calls
 (bsc#1179960).

CVE-2020-29371: Fixed uninitialized memory leaks to userspace
 (bsc#1179429).

CVE-2020-29660: Fixed a locking inconsistency in the tty subsystem that
 may have allowed a read-after-free attack against TIOCGSID (bnc#1179745).

CVE-2020-29661: Fixed a locking issue in the tty subsystem that allowed
 a use-after-free attack against TIOCSPGRP (bsc#1179745).

The following non-security bugs were fixed:

ALSA: hda/ca0132 - Change Input Source enum strings (git-fixes).

ALSA: hda/ca0132 - Fix AE-5 rear headphone pincfg (git-fixes).

ALSA: hda/realtek - Add new codec supported for ALC897 (git-fixes).

ALSA: hda/realtek: Add mute LED quirk to yet another HP x360 model
 (git-fixes).

ALSA: hda/realtek: Add some Clove SSID in the ALC293(ALC1220)
 (git-fixes).

ALSA: hda/realtek: Enable headset of ASUS UX482EG & B9400CEA with ALC294
 (git-fixes).

ALSA: hda: Fix regressions on clear and reconfig sysfs (git-fixes).

ALSA: usb-audio: US16x08: fix value count for level meters (git-fixes).

ASoC: arizona: Fix a wrong free in wm8997_probe (git-fixes).

ASoC: cx2072x: Fix doubly definitions of Playback and Capture streams
 (git-fixes).

ASoC: jz4740-i2s: add missed checks for clk_get() (git-fixes).

ASoC: pcm: DRAIN support reactivation (git-fixes).

ASoC: ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~16.41.1", rls: "SLES12.0SP5" ) )){
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

