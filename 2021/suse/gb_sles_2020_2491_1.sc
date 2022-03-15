if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2491.1" );
	script_cve_id( "CVE-2019-0155", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14895", "CVE-2019-14901", "CVE-2019-16746", "CVE-2019-18680", "CVE-2019-19447", "CVE-2019-9458", "CVE-2020-11668", "CVE-2020-14331" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-12 16:15:00 +0000 (Thu, 12 Dec 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2491-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2491-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202491-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Linux Kernel (Live Patch 32 for SLE 12 SP2)' package(s) announced via the SUSE-SU-2020:2491-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for the Linux Kernel 4.4.121-92_120 fixes several issues.

The following security issues were fixed:

CVE-2020-14331: Fixed a buffer over-write in vgacon_scroll (bsc#1174247).

CVE-2019-0155: Fixed a privilege escalation in the i915 graphics driver
 (bsc#1173663).

CVE-2019-16746: Fixed a buffer overflow in net/wireless/nl80211.c
 (bsc#1173659).

CVE-2019-9458: Fixed a use-after-free in media/v4l (bsc#1173963).

CVE-2020-11668: Fixed a memory corruption issue in the Xirlink camera
 USB driver (bsc#1173942).

CVE-2019-19447: Fixed a use-after-free in ext4_put_super (bsc#1173869).

CVE-2019-18680: Fixed a NULL pointer dereference in rds_tcp_kill_sock()
 in net/rds/tcp.c (bsc#1173867).

CVE-2019-14816: Fixed a heap-based buffer overflow in the Marvell WiFi
 driver (bsc#1173666).

CVE-2019-14814: Fixed a heap-based buffer overflow in the Marvell WiFi
 driver (bsc#1173664).

CVE-2019-14815: Fixed a heap-based buffer overflow in the Marvell WiFi
 driver (bsc#1173665).

CVE-2019-14901: Fixed a heap overflow in the Marvell WiFi driver
 (bsc#1173661).

CVE-2019-14895: Fixed a heap-based buffer overflow in the Marvell WiFi
 driver (bsc#1173100)." );
	script_tag( name: "affected", value: "'Linux Kernel (Live Patch 32 for SLE 12 SP2)' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_121-92_120-default", rpm: "kgraft-patch-4_4_121-92_120-default~9~2.2", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_103-default", rpm: "kgraft-patch-4_4_180-94_103-default~9~2.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "kgraft-patch-4_4_180-94_103-default-debuginfo", rpm: "kgraft-patch-4_4_180-94_103-default-debuginfo~9~2.2", rls: "SLES12.0SP3" ) )){
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

