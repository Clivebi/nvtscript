if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.0424.1" );
	script_cve_id( "CVE-2016-10396" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-27 17:52:00 +0000 (Thu, 27 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:0424-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:0424-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20180424-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ipsec-tools' package(s) announced via the SUSE-SU-2018:0424-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for ipsec-tools fixes one issue.
This security issue was fixed:
- CVE-2016-10396: The racoon daemon contained a remotely exploitable
 computational-complexity attack when parsing and storing ISAKMP
 fragments that allowed a remote attacker to exhaust computational
 resources on the remote endpoint by repeatedly sending ISAKMP fragment
 packets in a particular order (bsc#1047443)." );
	script_tag( name: "affected", value: "'ipsec-tools' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools", rpm: "ipsec-tools~0.8.0~19.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools-debuginfo", rpm: "ipsec-tools-debuginfo~0.8.0~19.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools-debugsource", rpm: "ipsec-tools-debugsource~0.8.0~19.3.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools", rpm: "ipsec-tools~0.8.0~19.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools-debuginfo", rpm: "ipsec-tools-debuginfo~0.8.0~19.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ipsec-tools-debugsource", rpm: "ipsec-tools-debugsource~0.8.0~19.3.1", rls: "SLES12.0SP3" ) )){
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
