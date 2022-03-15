if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3034.1" );
	script_cve_id( "CVE-2020-0556", "CVE-2020-27153" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:51 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 19:15:00 +0000 (Mon, 09 Nov 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3034-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3034-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203034-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bluez' package(s) announced via the SUSE-SU-2020:3034-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bluez fixes the following issues:

CVE-2020-27153: Fixed crash on disconnect (bsc#1177895).

CVE-2020-0556: Fixed potential escalation of privilege and denial of
 service via adjacent access, caused by improper access control
 (bsc#1166751)." );
	script_tag( name: "affected", value: "'bluez' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Workstation Extension 15-SP2." );
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "bluez", rpm: "bluez~5.48~13.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-debuginfo", rpm: "bluez-debuginfo~5.48~13.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-debugsource", rpm: "bluez-debugsource~5.48~13.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3", rpm: "libbluetooth3~5.48~13.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libbluetooth3-debuginfo", rpm: "libbluetooth3-debuginfo~5.48~13.3.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bluez-devel", rpm: "bluez-devel~5.48~13.3.1", rls: "SLES15.0SP2" ) )){
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

