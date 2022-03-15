if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1248.1" );
	script_cve_id( "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-36311", "CVE-2021-20219", "CVE-2021-29154", "CVE-2021-30002", "CVE-2021-3483" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-02 12:15:00 +0000 (Fri, 02 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1248-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1248-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211248-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:1248-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The SUSE Linux Enterprise 12 SP5 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2020-25670, CVE-2020-25671, CVE-2020-25672, CVE-2020-25673: Fixed
 multiple bugs in NFC subsystem (bsc#1178181).

CVE-2020-36311: Fixed a denial of service (soft lockup) by triggering
 destruction of a large SEV VM (bsc#1184511).

CVE-2021-29154: Fixed incorrect computation of branch displacements,
 allowing arbitrary code execution (bsc#1184391).

CVE-2021-30002: Fixed a memory leak for large arguments in
 video_usercopy (bsc#1184120).

CVE-2021-3483: Fixed a use-after-free in nosy.c (bsc#1184393).

CVE-2021-20219: Fixed a denial of service in n_tty_receive_char_special
 (bsc#1184397).

The following non-security bugs were fixed:

cifs: do not send close in compound create+close requests (bsc#1181507).

net: sched: disable TCQ_F_NOLOCK for pfifo_fast (bsc#1183405)

powerpc/64s: Fix instruction encoding for lis in ppc_function_entry()
 (bsc#1065729).

powerpc/pmem: Include pmem prototypes (bsc#1113295 git-fixes).

powerpc/pseries/ras: Remove unused variable 'status' (bsc#1065729).

s390/pci: Fix s390_mmio_read/write with MIO (LTC#192079 bsc#1183755).

vsprintf: Do not have bprintf dereference pointers (bsc#1184494).

vsprintf: Do not preprocess non-dereferenced pointers for bprintf (%px
 and %pK) (bsc#1184494).

vsprintf: Fix off-by-one bug in bstr_printf() processing dereferenced
 pointers (bsc#1184494).

x86/mem_encrypt: Correct physical address calculation in
 __set_clr_pte_enc() (12sp5).

xen/events: fix setting irq affinity (bsc#1184583)." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure", rpm: "kernel-azure~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base", rpm: "kernel-azure-base~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-base-debuginfo", rpm: "kernel-azure-base-debuginfo~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debuginfo", rpm: "kernel-azure-debuginfo~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-debugsource", rpm: "kernel-azure-debugsource~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-azure-devel", rpm: "kernel-azure-devel~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-devel-azure", rpm: "kernel-devel-azure~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-source-azure", rpm: "kernel-source-azure~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kernel-syms-azure", rpm: "kernel-syms-azure~4.12.14~16.53.1", rls: "SLES12.0SP5" ) )){
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

