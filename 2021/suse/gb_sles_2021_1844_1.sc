if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.1844.1" );
	script_cve_id( "CVE-2021-3560" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-09 15:03:36 +0000 (Wed, 09 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:1844-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:1844-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20211844-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'polkit' package(s) announced via the SUSE-SU-2021:1844-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for polkit fixes the following issues:

CVE-2021-3560: Fixed a local privilege escalation using
 polkit_system_bus_name_get_creds_sync() (bsc#1186497)." );
	script_tag( name: "affected", value: "'polkit' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libpolkit0", rpm: "libpolkit0~0.114~3.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpolkit0-debuginfo", rpm: "libpolkit0-debuginfo~0.114~3.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit", rpm: "polkit~0.114~3.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-debuginfo", rpm: "polkit-debuginfo~0.114~3.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-debugsource", rpm: "polkit-debugsource~0.114~3.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-devel", rpm: "polkit-devel~0.114~3.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-devel-debuginfo", rpm: "polkit-devel-debuginfo~0.114~3.12.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Polkit-1_0", rpm: "typelib-1_0-Polkit-1_0~0.114~3.12.1", rls: "SLES15.0" ) )){
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libpolkit0", rpm: "libpolkit0~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpolkit0-debuginfo", rpm: "libpolkit0-debuginfo~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit", rpm: "polkit~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-debuginfo", rpm: "polkit-debuginfo~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-debugsource", rpm: "polkit-debugsource~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-devel", rpm: "polkit-devel~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "polkit-devel-debuginfo", rpm: "polkit-devel-debuginfo~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Polkit-1_0", rpm: "typelib-1_0-Polkit-1_0~0.114~3.12.1", rls: "SLES15.0SP1" ) )){
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

