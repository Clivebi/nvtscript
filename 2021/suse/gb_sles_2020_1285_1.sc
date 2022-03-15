if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1285.1" );
	script_cve_id( "CVE-2020-1747" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-26 02:44:00 +0000 (Fri, 26 Mar 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:1285-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:1285-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20201285-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-PyYAML' package(s) announced via the SUSE-SU-2020:1285-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-PyYAML fixes the following issues:

CVE-2020-1747: Fixed an arbitrary code execution when YAML files are
 parsed by FullLoader (bsc#1165439)." );
	script_tag( name: "affected", value: "'python-PyYAML' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise High Availability 12-SP1, SUSE Linux Enterprise High Availability 12-SP2, SUSE Linux Enterprise Module for Advanced Systems Management 12, SUSE Linux Enterprise Module for Containers 12, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Point of Sale 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Manager Proxy 3.2, SUSE Manager Server 3.2, SUSE Manager Tools 12, SUSE OpenStack Cloud 6, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML", rpm: "python-PyYAML~5.1.2~26.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debuginfo", rpm: "python-PyYAML-debuginfo~5.1.2~26.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debugsource", rpm: "python-PyYAML-debugsource~5.1.2~26.12.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-PyYAML", rpm: "python3-PyYAML~5.1.2~26.12.1", rls: "SLES12.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML", rpm: "python-PyYAML~5.1.2~26.12.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debuginfo", rpm: "python-PyYAML-debuginfo~5.1.2~26.12.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debugsource", rpm: "python-PyYAML-debugsource~5.1.2~26.12.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-PyYAML", rpm: "python3-PyYAML~5.1.2~26.12.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML", rpm: "python-PyYAML~5.1.2~26.12.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debuginfo", rpm: "python-PyYAML-debuginfo~5.1.2~26.12.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debugsource", rpm: "python-PyYAML-debugsource~5.1.2~26.12.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-PyYAML", rpm: "python3-PyYAML~5.1.2~26.12.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-PyYAML-debuginfo", rpm: "python3-PyYAML-debuginfo~5.1.2~26.12.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML", rpm: "python-PyYAML~5.1.2~26.12.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debuginfo", rpm: "python-PyYAML-debuginfo~5.1.2~26.12.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-PyYAML-debugsource", rpm: "python-PyYAML-debugsource~5.1.2~26.12.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-PyYAML", rpm: "python3-PyYAML~5.1.2~26.12.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-PyYAML-debuginfo", rpm: "python3-PyYAML-debuginfo~5.1.2~26.12.1", rls: "SLES12.0SP5" ) )){
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

