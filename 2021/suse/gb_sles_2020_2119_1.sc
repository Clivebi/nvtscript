if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2119.1" );
	script_cve_id( "CVE-2019-16746", "CVE-2019-20908", "CVE-2020-0305", "CVE-2020-10135", "CVE-2020-10769", "CVE-2020-10773", "CVE-2020-10781", "CVE-2020-12771", "CVE-2020-12888", "CVE-2020-14331", "CVE-2020-14416", "CVE-2020-15393", "CVE-2020-15780" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2119-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2119-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202119-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2020:2119-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-15780: A lockdown bypass for loading unsigned modules using
 ACPI table injection was fixed. (bsc#1173573)

CVE-2020-15393: Fixed a memory leak in usbtest_disconnect (bnc#1173514).

CVE-2020-12771: An issue was discovered in btree_gc_coalesce in
 drivers/md/bcache/btree.c has a deadlock if a coalescing operation fails
 (bnc#1171732).

CVE-2020-12888: The VFIO PCI driver mishandled attempts to access
 disabled memory space (bnc#1171868).

CVE-2020-10773: Fixed a memory leak on s390/s390x, in the
 cmm_timeout_hander in file arch/s390/mm/cmm.c (bnc#1172999).

CVE-2020-14416: Fixed a race condition in tty->disc_data handling in the
 slip and slcan line discipline could lead to a use-after-free. This
 affects drivers/net/slip/slip.c and drivers/net/can/slcan.c
 (bnc#1162002).

CVE-2020-0305: Fixed a possible use-after-free due to a race condition
 incdev_get of char_dev.c. This could lead to local escalation of
 privilege. User interaction is not needed for exploitation (bnc#1174462).

CVE-2020-10769: A buffer over-read flaw was found in
 crypto_authenc_extractkeys in crypto/authenc.c in the IPsec
 Cryptographic algorithm's module, authenc. This flaw allowed a local
 attacker with user privileges to cause a denial of service (bnc#1173265).

CVE-2020-10781: Fixed a denial of service issue in the ZRAM
 implementation (bnc#1173074).

CVE-2019-20908: Fixed incorrect access permissions for the efivar_ssdt
 ACPI variable, which could be used by attackers to bypass lockdown or
 secure boot restrictions (bnc#1173567).

CVE-2019-16746: Fixed a buffer overflow in net/wireless/nl80211.c,
 related to invalid length checks for variable elements in a beacon head
 (bnc#1152107).

CVE-2020-10135: Legacy pairing and secure-connections pairing
 authentication in Bluetooth may have allowed an unauthenticated user to
 complete authentication without pairing credentials via adjacent access.
 An unauthenticated, adjacent attacker could impersonate a Bluetooth
 BR/EDR master or slave to pair with a previously paired remote device to
 successfully complete the authentication procedure without knowing the
 link key (bnc#1171988).

CVE-2020-14331: Fixed a buffer over write in vgacon_scrollback_update()
 (bnc#1174205).

The following non-security bugs were fixed:

ACPI: GED: add support for _Exx / _Lxx handler methods (bsc#1111666).

ACPI: GED: use correct trigger type field in _Exx / _Lxx handling
 (bsc#1111666).

ACPI: NFIT: Fix unlock on error in scrub_show() (bsc#1171753).

ACPI: sysfs: Fix pm_profile_attr type (bsc#1111666).

ACPI: video: Use native backlight on Acer Aspire 5783z (bsc#1111666).

ACPI: video: Use native backlight on Acer TravelMate 5735Z (bsc#1111666).

ALSA: hda - let hs_mic be picked ahead of hp_mic (bsc#1111666).

ALSA: hda/realtek - ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~16.22.1", rls: "SLES12.0SP5" ) )){
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

