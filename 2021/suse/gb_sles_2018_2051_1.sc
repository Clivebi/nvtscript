if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2051.1" );
	script_cve_id( "CVE-2018-13053", "CVE-2018-13405", "CVE-2018-13406", "CVE-2018-9385" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-05 20:15:00 +0000 (Tue, 05 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2051-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2051-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182051-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2051-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.140 to receive various security and bugfixes.
The following security bugs were fixed:
- CVE-2018-13053: The alarm_timer_nsleep function had an integer overflow
 via a large relative timeout because ktime_add_safe was not used
 (bnc#1099924)
- CVE-2018-9385: Prevent overread of the 'driver_override' buffer
 (bsc#1100491)
- CVE-2018-13405: The inode_init_owner function allowed local users to
 create files with an unintended group ownership allowing attackers to
 escalate privileges by making a plain file executable and SGID
 (bnc#1100416)
- CVE-2018-13406: An integer overflow in the uvesafb_setcmap function
 could have result in local attackers being able to crash the kernel or
 potentially elevate privileges because kmalloc_array is not used
 (bnc#1100418)
The following non-security bugs were fixed:
- 1wire: family module autoload fails because of upper/lower case mismatch
 (bnc#1012382).
- ALSA: hda - Clean up ALC299 init code (bsc#1099810).
- ALSA: hda - Enable power_save_node for CX20722 (bsc#1099810).
- ALSA: hda - Fix a wrong FIXUP for alc289 on Dell machines (bsc#1099810).
- ALSA: hda - Fix incorrect usage of IS_REACHABLE() (bsc#1099810).
- ALSA: hda - Fix pincfg at resume on Lenovo T470 dock (bsc#1099810).
- ALSA: hda - Handle kzalloc() failure in snd_hda_attach_pcm_stream()
 (bnc#1012382).
- ALSA: hda - Use acpi_dev_present() (bsc#1099810).
- ALSA: hda - add a new condition to check if it is thinkpad (bsc#1099810).
- ALSA: hda - silence uninitialized variable warning in activate_amp_in()
 (bsc#1099810).
- ALSA: hda/patch_sigmatel: Add AmigaOne X1000 pinconfigs (bsc#1099810).
- ALSA: hda/realtek - Add a quirk for FSC ESPRIMO U9210 (bsc#1099810).
- ALSA: hda/realtek - Add headset mode support for Dell laptop
 (bsc#1099810).
- ALSA: hda/realtek - Add support headset mode for DELL WYSE (bsc#1099810).
- ALSA: hda/realtek - Clevo P950ER ALC1220 Fixup (bsc#1099810).
- ALSA: hda/realtek - Enable Thinkpad Dock device for ALC298 platform
 (bsc#1099810).
- ALSA: hda/realtek - Enable mic-mute hotkey for several Lenovo AIOs
 (bsc#1099810).
- ALSA: hda/realtek - Fix Dell headset Mic can't record (bsc#1099810).
- ALSA: hda/realtek - Fix pop noise on Lenovo P50 and co (bsc#1099810).
- ALSA: hda/realtek - Fix the problem of two front mics on more machines
 (bsc#1099810).
- ALSA: hda/realtek - Fixup for HP x360 laptops with BandO speakers
 (bsc#1099810).
- ALSA: hda/realtek - Fixup mute led on HP Spectre x360 (bsc#1099810).
- ALSA: hda/realtek - Make dock sound work on ThinkPad L570 (bsc#1099810).
- ALSA: hda/realtek - Refactor alc269_fixup_hp_mute_led_mic*()
 (bsc#1099810).
- ALSA: hda/realtek - Reorder ALC269 ASUS quirk entries (bsc#1099810).
- ALSA: hda/realtek - Support headset mode for ALC215/ALC285/ALC289
 (bsc#1099810).
- ALSA: hda/realtek - Update ALC255 depop optimize (bsc#1099810).
- ALSA: hda/realtek - adjust the ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE CaaS Platform 3.0, SUSE CaaS Platform ALL, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise High Availability 12-SP3, SUSE Linux Enterprise Live Patching 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.140~94.42.1", rls: "SLES12.0SP3" ) )){
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

