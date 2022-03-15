if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.2159.1" );
	script_cve_id( "CVE-2019-10208" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:2159-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1|SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:2159-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20192159-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql96' package(s) announced via the SUSE-SU-2019:2159-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql96 fixes the following issues:

Security issue fixed:
CVE-2019-10208: Fixed arbitrary SQL execution via suitable SECURITY
 DEFINER function under the identity of the function owner (bsc#1145092)." );
	script_tag( name: "affected", value: "'postgresql96' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 4, SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP1, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql96", rpm: "postgresql96~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib", rpm: "postgresql96-contrib~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib-debuginfo", rpm: "postgresql96-contrib-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debuginfo", rpm: "postgresql96-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debugsource", rpm: "postgresql96-debugsource~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-docs", rpm: "postgresql96-docs~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-libs-debugsource", rpm: "postgresql96-libs-debugsource~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server", rpm: "postgresql96-server~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server-debuginfo", rpm: "postgresql96-server-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP1" ) )){
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql96", rpm: "postgresql96~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib", rpm: "postgresql96-contrib~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib-debuginfo", rpm: "postgresql96-contrib-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debuginfo", rpm: "postgresql96-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debugsource", rpm: "postgresql96-debugsource~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-docs", rpm: "postgresql96-docs~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-libs-debugsource", rpm: "postgresql96-libs-debugsource~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server", rpm: "postgresql96-server~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server-debuginfo", rpm: "postgresql96-server-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "postgresql96", rpm: "postgresql96~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib", rpm: "postgresql96-contrib~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-contrib-debuginfo", rpm: "postgresql96-contrib-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debuginfo", rpm: "postgresql96-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-debugsource", rpm: "postgresql96-debugsource~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-docs", rpm: "postgresql96-docs~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-libs-debugsource", rpm: "postgresql96-libs-debugsource~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server", rpm: "postgresql96-server~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql96-server-debuginfo", rpm: "postgresql96-server-debuginfo~9.6.15~3.29.1", rls: "SLES12.0SP3" ) )){
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

