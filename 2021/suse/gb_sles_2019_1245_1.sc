if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1245.1" );
	script_cve_id( "CVE-2018-1000204", "CVE-2018-10853", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-15594", "CVE-2018-5814", "CVE-2019-11091", "CVE-2019-3882", "CVE-2019-9503" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-29 15:17:00 +0000 (Wed, 29 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1245-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1245-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191245-1/" );
	script_xref( name: "URL", value: "https://www.suse.com/support/kb/doc/?id=7023736" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:1245-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP3 kernel was updated to 4.4.178 to receive various security and bugfixes.

Four new speculative execution issues have been identified in Intel CPUs.
(bsc#1111331)

CVE-2018-12126: Microarchitectural Store Buffer Data Sampling (MSBDS)

CVE-2018-12127: Microarchitectural Fill Buffer Data Sampling (MFBDS)

CVE-2018-12130: Microarchitectural Load Port Data Samling (MLPDS)

CVE-2019-11091: Microarchitectural Data Sampling Uncacheable Memory
 (MDSUM)

This kernel update contains software mitigations, utilizing CPU microcode updates shipped in parallel.

For more information on this set of information leaks, check out [link moved to references]

The following security issues fixed:

CVE-2018-5814: Multiple race condition errors when handling probe,
 disconnect, and rebind operations could be exploited to trigger a
 use-after-free condition or a NULL pointer dereference by sending
 multiple USB over IP packets (bnc#1096480).

CVE-2018-1000204: Prevent infoleak caused by incorrect handling of the
 SG_IO ioctl (bsc#1096728)

CVE-2018-10853: A flaw was found in the way the KVM hypervisor emulated
 instructions such as sgdt/sidt/fxsave/fxrstor. It did not check current
 privilege(CPL) level while emulating unprivileged instructions. An
 unprivileged guest user/process could use this flaw to potentially
 escalate privileges inside guest (bnc#1097104).

CVE-2018-15594: arch/x86/kernel/paravirt.c mishandled certain indirect
 calls, which made it easier for attackers to conduct Spectre-v2 attacks
 against paravirtual guests (bnc#1105348).

CVE-2019-9503: A brcmfmac frame validation bypass was fixed
 (bnc#1132828).

CVE-2019-3882: A flaw was fixed in the vfio interface implementation
 that permitted violation of the user's locked memory limit. If a device
 is bound to a vfio driver, such as vfio-pci, and the local attacker is
 administratively granted ownership of the device, it may cause a system
 memory exhaustion and thus a denial of service (DoS). Versions 3.10,
 4.14 and 4.18 are vulnerable (bnc#1131416 bnc#1131427).

The following non-security bugs were fixed:

9p/net: fix memory leak in p9_client_create (bnc#1012382).

9p: use inode->i_lock to protect i_size_write() under 32-bit
 (bnc#1012382).

acpi: acpi_pad: Do not launch acpi_pad threads on idle cpus
 (bsc#1113399).

acpi / bus: Only call dmi_check_system() on X86 (git-fixes).

acpi / button: make module loadable when booted in non-ACPI mode
 (bsc#1051510).

acpi / device_sysfs: Avoid OF modalias creation for removed device
 (bnc#1012382).

acpi: include ACPI button driver in base kernel (bsc#1062056).

Add hlist_add_tail_rcu() (Merge
 git://git.kernel.org/pub/scm/linux/kernel/git/davem/net) (bnc#1012382).

alsa: bebob: use more identical mod_alias for Saffire Pro 10 I/O against
 Liquid Saffire 56 (bnc#1012382).

alsa: compress: add support for 32bit calls in a 64bit kernel
 ... [Please see the references for more information on the vulnerabilities]" );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-default", rpm: "kernel-default~4.4.178~94.91.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base", rpm: "kernel-default-base~4.4.178~94.91.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-base-debuginfo", rpm: "kernel-default-base-debuginfo~4.4.178~94.91.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debuginfo", rpm: "kernel-default-debuginfo~4.4.178~94.91.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-debugsource", rpm: "kernel-default-debugsource~4.4.178~94.91.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-devel", rpm: "kernel-default-devel~4.4.178~94.91.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-default-man", rpm: "kernel-default-man~4.4.178~94.91.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel", rpm: "kernel-devel~4.4.178~94.91.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-macros", rpm: "kernel-macros~4.4.178~94.91.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source", rpm: "kernel-source~4.4.178~94.91.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms", rpm: "kernel-syms~4.4.178~94.91.1", rls: "SLES12.0SP3" ) )){
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

