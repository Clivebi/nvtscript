if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1143.1" );
	script_cve_id( "CVE-2016-9603", "CVE-2017-7718" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-07 10:29:00 +0000 (Fri, 07 Sep 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1143-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1143-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171143-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:1143-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes several issues.
These security issues were fixed:
- A malicious 64-bit PV guest may be able to access all of system memory,
 allowing for all of privilege escalation, host crashes, and information
 leaks by placing a IRET hypercall in the middle of a multicall batch
 (XSA-213, bsc#1034843)
- A malicious pair of guests may be able to access all of system memory,
 allowing for all of privilege escalation, host crashes, and information
 leaks because of a missing check when transfering pages via
 GNTTABOP_transfer (XSA-214, bsc#1034844).
- CVE-2017-7718: hw/display/cirrus_vga_rop.h allowed local guest OS
 privileged users to cause a denial of service (out-of-bounds read and
 QEMU process crash) via vectors related to copying VGA data via the
 cirrus_bitblt_rop_fwd_transp_ and cirrus_bitblt_rop_fwd_ functions
 (bsc#1034994).
- CVE-2016-9603: A privileged user within the guest VM could have caused a
 heap overflow in the device model process, potentially escalating their
 privileges to that of the device model process (bsc#1028655)
These non-security issues were fixed:
- bsc#1029827: Additional xenstore patch
- bsc#1036146: Xen VM dumped core to wrong path
- bsc#1022703: Prevent Xen HVM guest with OVMF to hang with unattached
 CDRom" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-debugsource", rpm: "xen-debugsource~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo-32bit", rpm: "xen-libs-debuginfo-32bit~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-debuginfo", rpm: "xen-libs-debuginfo~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-debuginfo", rpm: "xen-tools-debuginfo~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU-debuginfo", rpm: "xen-tools-domU-debuginfo~4.7.2_04~39.1", rls: "SLES12.0SP2" ) )){
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

