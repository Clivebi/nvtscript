if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3715.1" );
	script_cve_id( "CVE-2020-15437", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-27777", "CVE-2020-28915", "CVE-2020-28974", "CVE-2020-8694" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-02 12:15:00 +0000 (Fri, 02 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3715-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3715-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203715-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:3715-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-15437: Fixed a null pointer dereference which could have
 allowed local users to cause a denial of service(bsc#1179140).

CVE-2020-27777: Restrict RTAS requests from userspace (bsc#1179107).

CVE-2020-28974: Fixed a slab-out-of-bounds read in fbcon which could
 have been used by local attackers to read privileged information or
 potentially crash the kernel (bsc#1178589).

CVE-2020-28915: Fixed a buffer over-read in the fbcon code which could
 have been used by local attackers to read kernel memory (bsc#1178886).

CVE-2020-8694: Insufficient access control for some Intel(R) Processors
 may have allowed an authenticated user to potentially enable information
 disclosure via local access (bsc#1170415).

CVE-2020-25668: Fixed a use-after-free in con_font_op() (bsc#1178123).

CVE-2020-25704: Fixed a memory leak in perf_event_parse_addr_filter()
 (bsc#1178393).

CVE-2020-25669: Fixed a use-after-free read in sunkbd_reinit()
 (bsc#1178182).

The following non-security bugs were fixed:

9P: Cast to loff_t before multiplying (git-fixes).

acpi-cpufreq: Honor _PSD table setting on new AMD CPUs (git-fixes).

ACPI: debug: do not allow debugging when ACPI is disabled (git-fixes).

ACPI / extlog: Check for RDMSR failure (git-fixes).

ACPI: GED: fix -Wformat (git-fixes).

ACPI: NFIT: Fix comparison to '-ENXIO' (git-fixes).

ACPI: video: use ACPI backlight for HP 635 Notebook (git-fixes).

ALSA: ctl: fix error path at adding user-defined element set (git-fixes).

ALSA: firewire: Clean up a locking issue in copy_resp_to_buf()
 (git-fixes).

ALSA: hda - Fix the return value if cb func is already registered
 (git-fixes).

ALSA: hda - Fix the return value if cb func is already registered
 (git-fixes).

ALSA: hda: prevent undefined shift in snd_hdac_ext_bus_get_link()
 (git-fixes).

ALSA: mixart: Fix mutex deadlock (git-fixes).

ALSA: usb-audio: Fix potential use-after-free of streams (gix-fixes).

arm64: KVM: Fix system register enumeration (bsc#1174726).

arm64: Run ARCH_WORKAROUND_1 enabling code on all CPUs (git-fixes).

arm/arm64: KVM: Add PSCI version selection API (bsc#1174726).

ASoC: qcom: lpass-platform: Fix memory leak (git-fixes).

ata: sata_rcar: Fix DMA boundary mask (git-fixes).

ath10k: Acquire tx_lock in tx error paths (git-fixes).

ath10k: fix VHT NSS calculation when STBC is enabled (git-fixes).

ath10k: start recovery process when payload length exceeds max htc
 length for sdio (git-fixes).

batman-adv: set .owner to THIS_MODULE (git-fixes).

Bluetooth: btusb: Fix and detect most of the Chinese Bluetooth
 controllers (git-fixes).

Bluetooth: hci_bcm: fix freeing not-requested IRQ (git-fixes).

bpf: Zero-fill re-used per-cpu map element (git-fixes).

btrfs: account ticket size at add/delete time (bsc#1178897).

btrfs: add ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~16.38.1", rls: "SLES12.0SP5" ) )){
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

