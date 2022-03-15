if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1908.1" );
	script_cve_id( "CVE-2014-0222", "CVE-2015-4037", "CVE-2015-5239", "CVE-2015-6815", "CVE-2015-7311", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7971" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-28 21:34:00 +0000 (Tue, 28 Jan 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1908-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1908-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151908-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2015:1908-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "xen was updated to version 4.4.3 to fix nine security issues.
These security issues were fixed:
- CVE-2015-4037: The slirp_smb function in net/slirp.c created temporary
 files with predictable names, which allowed local users to cause a
 denial of service (instantiation failure) by creating /tmp/qemu-smb.*-*
 files before the program (bsc#932267).
- CVE-2014-0222: Integer overflow in the qcow_open function allowed remote
 attackers to cause a denial of service (crash) via a large L2 table in a
 QCOW version 1 image (bsc#877642).
- CVE-2015-7835: Uncontrolled creation of large page mappings by PV guests
 (bsc#950367).
- CVE-2015-7311: libxl in Xen did not properly handle the readonly flag on
 disks when using the qemu-xen device model, which allowed local guest
 users to write to a read-only disk image (bsc#947165).
- CVE-2015-5239: Integer overflow in vnc_client_read() and
 protocol_client_msg() (bsc#944463).
- CVE-2015-6815: With e1000 NIC emulation support it was possible to enter
 an infinite loop (bsc#944697).
- CVE-2015-7969: Leak of main per-domain vcpu pointer array leading to
 denial of service (bsc#950703).
- CVE-2015-7969: Leak of per-domain profiling- related vcpu pointer array
 leading to denial of service (bsc#950705).
- CVE-2015-7971: Some pmu and profiling hypercalls log without rate
 limiting (bsc#950706).
These non-security issues were fixed:
- bsc#907514: Bus fatal error: SLES 12 sudden reboot has been observed
- bsc#910258: SLES12 Xen host crashes with FATAL NMI after shutdown of
 guest with VT-d NIC
- bsc#918984: Bus fatal error: SLES11-SP4 sudden reboot has been observed
- bsc#923967: Partner-L3: Bus fatal error: SLES11-SP3 sudden reboot has
 been observed
- bnc#901488: Intel ixgbe driver assigns rx/tx queues per core resulting
 in irq problems on servers with a large amount of CPU cores
- bsc#945167: Running command: xl pci-assignable-add 03:10.1 secondly show
 errors
- bsc#949138: Setting vcpu affinity under Xen causes libvirtd abort" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.4.3_02_k3.12.48_52.27~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default-debuginfo", rpm: "xen-kmp-default-debuginfo~4.4.3_02_k3.12.48_52.27~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.4.3_02~22.12.1", rls: "SLES12.0" ) )){
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

