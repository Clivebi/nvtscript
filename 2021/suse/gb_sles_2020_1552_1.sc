if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1552.1" );
	script_cve_id( "CVE-2020-10722", "CVE-2020-10723", "CVE-2020-10724" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1552-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1552-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201552-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dpdk' package(s) announced via the SUSE-SU-2020:1552-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dpdk fixes the following issues:

CVE-2020-10722: Fixed an integer overflow in vhost_user_set_log_base()
 (bsc#1171930).

CVE-2020-10723: Fixed an integer truncation in
 vhost_user_check_and_alloc_queue_pair() (bsc#1171925).

CVE-2020-10724: Fixed a missing inputs validation in Vhost-crypto
 (bsc#1171926)." );
	script_tag( name: "affected", value: "'dpdk' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5." );
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
	if(!isnull( res = isrpmvuln( pkg: "dpdk", rpm: "dpdk~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debuginfo", rpm: "dpdk-debuginfo~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-debugsource", rpm: "dpdk-debugsource~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default", rpm: "dpdk-kmp-default~18.11.3_k4.12.14_122.20~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-kmp-default-debuginfo", rpm: "dpdk-kmp-default-debuginfo~18.11.3_k4.12.14_122.20~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx", rpm: "dpdk-thunderx~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debuginfo", rpm: "dpdk-thunderx-debuginfo~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-debugsource", rpm: "dpdk-thunderx-debugsource~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default", rpm: "dpdk-thunderx-kmp-default~18.11.3_k4.12.14_122.20~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-thunderx-kmp-default-debuginfo", rpm: "dpdk-thunderx-kmp-default-debuginfo~18.11.3_k4.12.14_122.20~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools", rpm: "dpdk-tools~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dpdk-tools-debuginfo", rpm: "dpdk-tools-debuginfo~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-18_11", rpm: "libdpdk-18_11~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdpdk-18_11-debuginfo", rpm: "libdpdk-18_11-debuginfo~18.11.3~3.9.2", rls: "SLES12.0SP5" ) )){
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

