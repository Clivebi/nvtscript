if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.14704.1" );
	script_cve_id( "CVE-2014-3689", "CVE-2015-1779", "CVE-2020-12829", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13765", "CVE-2020-14364", "CVE-2020-25084", "CVE-2020-25624", "CVE-2020-25625", "CVE-2020-25723", "CVE-2020-29130", "CVE-2020-29443", "CVE-2021-20181", "CVE-2021-20257" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:39 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 11:40:00 +0000 (Mon, 05 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:14704-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:14704-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-202114704-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2021:14704-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kvm fixes the following issues:

Fix OOB read and write due to integer overflow in sm501_2d_operation()
 in hw/display/sm501.c (CVE-2020-12829, bsc#1172385)

Fix OOB access possibility in MegaRAID SAS 8708EM2 emulation
 (CVE-2020-13362 bsc#1172383)

Fix use-after-free in usb xhci packet handling (CVE-2020-25723,
 bsc#1178934)

Fix use-after-free in usb ehci packet handling (CVE-2020-25084,
 bsc#1176673)

Fix OOB access in usb hcd-ohci emulation (CVE-2020-25624, bsc#1176682)

Fix infinite loop (DoS) in usb hcd-ohci emulation (CVE-2020-25625,
 bsc#1176684)

Fix OOB access in atapi emulation (CVE-2020-29443, bsc#1181108)

Fix DoS in e1000 emulated device (CVE-2021-20257 bsc#1182577)

Fix OOB access in SLIRP ARP packet processing (CVE-2020-29130,
 bsc#1179467)

Fix OOB access while processing USB packets (CVE-2020-14364 bsc#1175441)

Fix potential privilege escalation in virtfs (CVE-2021-20181 bsc#1182137)

Fix package scripts to not use hard coded paths for temporary working
 directories and log files (bsc#1182425)

Fix OOB access possibility in ES1370 audio device emulation
 (CVE-2020-13361 bsc#1172384)

Fix OOB access in ROM loading (CVE-2020-13765 bsc#1172478)" );
	script_tag( name: "affected", value: "'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "kvm", rpm: "kvm~1.4.2~60.34.1", rls: "SLES11.0SP4" ) )){
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

