if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.1770.1" );
	script_cve_id( "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8905", "CVE-2017-9330", "CVE-2017-9374", "CVE-2017-9503" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:55 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:1770-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:1770-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20171770-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2017:1770-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for xen fixes several issues.
These security issues were fixed:
- blkif responses leaked backend stack data, which allowed unprivileged
 guest to obtain sensitive information from the host or other guests
 (XSA-216, bsc#1042863)
- Page transfer might have allowed PV guest to elevate privilege (XSA-217,
 bsc#1042882)
- Races in the grant table unmap code allowed for informations leaks and
 potentially privilege escalation (XSA-218, bsc#1042893)
- Insufficient reference counts during shadow emulation allowed a
 malicious pair of guest to elevate their privileges to the privileges
 that XEN runs under (XSA-219, bsc#1042915)
- Stale P2M mappings due to insufficient error checking allowed malicious
 guest to leak information or elevate privileges (XSA-222, bsc#1042931)
- Grant table operations mishandled reference counts allowing malicious
 guests to escape (XSA-224, bsc#1042938)
- CVE-2017-9330: USB OHCI Emulation in qemu allowed local guest OS users
 to cause a denial of service (infinite loop) by leveraging an incorrect
 return value (bsc#1042160)
- CVE-2017-8309: Memory leak in the audio/audio.c allowed remote attackers
 to cause a denial of service (memory consumption) by repeatedly starting
 and stopping audio capture (bsc#1037243)
- CVE-2017-8905: Xen a failsafe callback, which might have allowed PV
 guest OS users to execute arbitrary code on the host OS (XSA-215,
 bsc#1034845).
- CVE-2017-9503: The MegaRAID SAS 8708EM2 Host Bus Adapter emulation
 support was vulnerable to a null pointer dereference issue which allowed
 a privileged user inside guest to crash the Qemu process on the host
 resulting in DoS (bsc#1043297)
- CVE-2017-9374: Missing free of 's->ipacket', causes a host memory leak,
 allowing for DoS (bsc#1043074)
- CVE-2017-8112: hw/scsi/vmw_pvscsi.c allowed local guest OS privileged
 users to cause a denial of service (infinite loop and CPU consumption)
 via the message ring page count (bsc#1036470)
- Missing NULL pointer check in event channel poll allows guests to DoS
 the host (XSA-221, bsc#1042924)
These non-security issues were fixed:
- bsc#1032148: Ensure that time doesn't goes backwards during live
 migration of HVM domU
- bsc#1031460: Fixed DomU Live Migration
- bsc#1014136: Fixed kdump SLES12-SP2
- bsc#1026236: Equalized paravirtualized vs. fully virtualized migration
 speed" );
	script_tag( name: "affected", value: "'xen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "xen", rpm: "xen~4.4.4_20~60.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-doc-html", rpm: "xen-doc-html~4.4.4_20~60.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-default", rpm: "xen-kmp-default~4.4.4_20_3.0.101_104~60.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-kmp-pae", rpm: "xen-kmp-pae~4.4.4_20_3.0.101_104~60.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs-32bit", rpm: "xen-libs-32bit~4.4.4_20~60.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-libs", rpm: "xen-libs~4.4.4_20~60.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools", rpm: "xen-tools~4.4.4_20~60.3", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xen-tools-domU", rpm: "xen-tools-domU~4.4.4_20~60.3", rls: "SLES11.0SP4" ) )){
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

