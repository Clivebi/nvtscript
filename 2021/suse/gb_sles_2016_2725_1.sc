if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2725.1" );
	script_cve_id( "CVE-2014-3615", "CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4480", "CVE-2016-5238", "CVE-2016-5338", "CVE-2016-5403", "CVE-2016-6258", "CVE-2016-6351", "CVE-2016-7092", "CVE-2016-7094" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-14 19:54:00 +0000 (Mon, 14 Dec 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2725-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2725-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162725-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2016:2725-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes several issues.
These security issues were fixed:
- CVE-2016-7094: Buffer overflow in Xen allowed local x86 HVM guest OS
 administrators on guests running with shadow paging to cause a denial of
 service via a pagetable update (bsc#995792)
- CVE-2016-7092: The get_page_from_l3e function in arch/x86/mm.c in Xen
 allowed local 32-bit PV guest OS administrators to gain host OS
 privileges via vectors related to L3 recursive pagetables (bsc#995785)
- CVE-2016-5403: Unbounded memory allocation allowed a guest administrator
 to cause a denial of service of the host (bsc#990923)
- CVE-2016-6351: The esp_do_dma function in hw/scsi/esp.c, when built with
 ESP/NCR53C9x controller emulation support, allowed local guest OS
 administrators to cause a denial of service (out-of-bounds write and
 QEMU process crash) or execute arbitrary code on the host via vectors
 involving DMA read into ESP command buffer (bsc#990843)
- CVE-2016-6258: The PV pagetable code in arch/x86/mm.c in Xen allowed
 local 32-bit PV guest OS administrators to gain host OS privileges by
 leveraging fast-paths for updating pagetable entries (bsc#988675)
- CVE-2016-5338: The (1) esp_reg_read and (2) esp_reg_write functions
 allowed local guest OS administrators to cause a denial of service (QEMU
 process crash) or execute arbitrary code on the host via vectors related
 to the information transfer buffer (bsc#983984)
- CVE-2016-5238: The get_cmd function in hw/scsi/esp.c might have allowed
 local guest OS administrators to cause a denial of service
 (out-of-bounds write and QEMU process crash) via vectors related to
 reading from the information transfer buffer in non-DMA mode (bsc#982960)
- CVE-2016-4453: The vmsvga_fifo_run function allowed local guest OS
 administrators to cause a denial of service (infinite loop and QEMU
 process crash) via a VGA command (bsc#982225)
- CVE-2016-4454: The vmsvga_fifo_read_raw function allowed local guest OS
 administrators to obtain sensitive host memory information or cause a
 denial of service (QEMU process crash) by changing FIFO registers and
 issuing a VGA command, which triggered an out-of-bounds read (bsc#982224)
- CVE-2014-3672: The qemu implementation in libvirt Xen allowed local
 guest OS users to cause a denial of service (host disk consumption) by
 writing to stdout or stderr (bsc#981264)
- CVE-2016-4441: The get_cmd function in the 53C9X Fast SCSI Controller
 (FSC) support did not properly check DMA length, which allowed local
 guest OS administrators to cause a denial of service (out-of-bounds
 write and QEMU process crash) via unspecified vectors, involving an SCSI
 command (bsc#980724)
- CVE-2016-4439: The esp_reg_write function in the 53C9X Fast SCSI
 Controller (FSC) support did not properly check command buffer length,
 which allowed local guest OS administrators to cause a denial of service
 (out-of-bounds write and QEMU process ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Manager 2.1, SUSE Manager Proxy 2.1, SUSE OpenStack Cloud 5." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.2.5_21~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.2.5_21~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-pdf", rpm: "xen-doc-pdf~4.2.5_21~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.2.5_21_3.0.101_0.47.86~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-pae", rpm: "xen-kmp-pae~4.2.5_21_3.0.101_0.47.86~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.2.5_21~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.2.5_21~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.2.5_21~27.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.2.5_21~27.1", rls: "SLES11.0SP3" ) )){
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

