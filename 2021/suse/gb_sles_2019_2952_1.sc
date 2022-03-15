if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2952.1" );
	script_cve_id( "CVE-2018-12207", "CVE-2019-10220", "CVE-2019-11135", "CVE-2019-16232", "CVE-2019-16233", "CVE-2019-16234", "CVE-2019-16995", "CVE-2019-17056", "CVE-2019-17133", "CVE-2019-17666" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2952-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2952-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192952-1/" );
	script_xref( name: "URL", value: "https://www.suse.com/support/kb/doc/?id=7023735" );
	script_xref( name: "URL", value: "https://www.suse.com/support/kb/doc/?id=7024251" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2019:2952-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 15-SP1 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-12207: Untrusted virtual machines on Intel CPUs could exploit a
 race condition in the Instruction Fetch Unit of the Intel CPU to cause a
 Machine Exception during Page Size Change, causing the CPU core to be
 non-functional.

 The Linux Kernel kvm hypervisor was adjusted to avoid page size changes in executable pages by splitting / merging huge pages into small pages as More information can be found on [link moved to references] CVE-2019-11135: Aborting an asynchronous TSX operation on Intel CPUs
 with Transactional Memory support could be used to facilitate
 sidechannel information leaks out of microarchitectural buffers, similar
 to the previously described 'Microarchitectural Data Sampling' attack.

 The Linux kernel was supplemented with the option to disable TSX operation altogether (requiring CPU Microcode updates on older systems)
and better flushing of microarchitectural buffers (VERW).

 The set of options available is described in our TID at [link moved to references] CVE-2019-16995: Fix a memory leak in hsr_dev_finalize() if hsr_add_port
 failed to add a port, which may have caused denial of service
 (bsc#1152685).
CVE-2019-16233: drivers/scsi/qla2xxx/qla_os.c did not check the
 alloc_workqueue return value, leading to a NULL pointer dereference.
 (bsc#1150457).
CVE-2019-10220: Added sanity checks on the pathnames passed to the user
 space. (bsc#1144903).
CVE-2019-17666: rtlwifi: Fix potential overflow in P2P code
 (bsc#1154372).
CVE-2019-16232: Fix a potential NULL pointer dereference in the Marwell
 libertas driver (bsc#1150465).
CVE-2019-16234: iwlwifi pcie driver did not check the alloc_workqueue
 return value, leading to a NULL pointer dereference. (bsc#1150452).
CVE-2019-17133: cfg80211 wireless extension did not reject a long SSID
 IE, leading to a Buffer Overflow (bsc#1153158).
CVE-2019-17056: The AF_NFC network module did not enforce CAP_NET_RAW,
 which meant that unprivileged users could create a raw socket
 (bsc#1152788).

The following non-security bugs were fixed:
9p: avoid attaching writeback_fid on mmap with type PRIVATE
 (bsc#1051510).

Add kernel module compression support (bsc#1135854)

acpi / CPPC: do not require the _PSD method (bsc#1051510).

acpi / processor: do not print errors for processorIDs == 0xff
 (bsc#1051510).

acpi: CPPC: Set pcc_data[pcc_ss_id] to NULL in
 acpi_cppc_processor_exit() (bsc#1051510).

act_mirred: Fix mirred_init_module error handling (bsc#1051510).

alsa: bebob: Fix prototype of helper function to return negative value
 (bsc#1051510).

alsa: firewire-motu: add support for MOTU 4pre (bsc#1111666).

alsa: hda - Add a quirk model for fixing Huawei Matebook X right speaker
 (bsc#1051510).

alsa: hda - Add laptop imic fixup for ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~8.19.1", rls: "SLES15.0SP1" ) )){
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

