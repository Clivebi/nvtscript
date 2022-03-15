if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0425.1" );
	script_cve_id( "CVE-2020-17525" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-04 09:15:00 +0000 (Tue, 04 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0425-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3|SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0425-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210425-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'subversion' package(s) announced via the SUSE-SU-2021:0425-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for subversion fixes the following issues:

CVE-2020-17525: A null-pointer-dereference has been found in
 mod_authz_svn that results in a remote unauthenticated Denial-of-Service
 in some server configurations (bsc#1181687)." );
	script_tag( name: "affected", value: "'subversion' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE Linux Enterprise Module for Server Applications 15-SP2, SUSE Linux Enterprise Module for Server Applications 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "subversion", rpm: "subversion~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debuginfo", rpm: "subversion-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debugsource", rpm: "subversion-debugsource~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-devel", rpm: "subversion-devel~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-bash-completion", rpm: "subversion-bash-completion~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl", rpm: "subversion-perl~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl-debuginfo", rpm: "subversion-perl-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python", rpm: "subversion-python~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python-debuginfo", rpm: "subversion-python-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools", rpm: "subversion-tools~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools-debuginfo", rpm: "subversion-tools-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server", rpm: "subversion-server~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server-debuginfo", rpm: "subversion-server-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "subversion", rpm: "subversion~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debuginfo", rpm: "subversion-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debugsource", rpm: "subversion-debugsource~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-devel", rpm: "subversion-devel~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-bash-completion", rpm: "subversion-bash-completion~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl", rpm: "subversion-perl~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl-debuginfo", rpm: "subversion-perl-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python", rpm: "subversion-python~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python-debuginfo", rpm: "subversion-python-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools", rpm: "subversion-tools~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools-debuginfo", rpm: "subversion-tools-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server", rpm: "subversion-server~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server-debuginfo", rpm: "subversion-server-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP3" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "subversion", rpm: "subversion~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-bash-completion", rpm: "subversion-bash-completion~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debuginfo", rpm: "subversion-debuginfo~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debugsource", rpm: "subversion-debugsource~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-devel", rpm: "subversion-devel~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl", rpm: "subversion-perl~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl-debuginfo", rpm: "subversion-perl-debuginfo~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python", rpm: "subversion-python~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python-debuginfo", rpm: "subversion-python-debuginfo~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server", rpm: "subversion-server~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server-debuginfo", rpm: "subversion-server-debuginfo~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools", rpm: "subversion-tools~1.10.6~3.15.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools-debuginfo", rpm: "subversion-tools-debuginfo~1.10.6~3.15.1", rls: "SLES15.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "subversion", rpm: "subversion~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-bash-completion", rpm: "subversion-bash-completion~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debuginfo", rpm: "subversion-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-debugsource", rpm: "subversion-debugsource~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-devel", rpm: "subversion-devel~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl", rpm: "subversion-perl~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-perl-debuginfo", rpm: "subversion-perl-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python", rpm: "subversion-python~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-python-debuginfo", rpm: "subversion-python-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server", rpm: "subversion-server~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-server-debuginfo", rpm: "subversion-server-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools", rpm: "subversion-tools~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "subversion-tools-debuginfo", rpm: "subversion-tools-debuginfo~1.10.6~3.15.1", rls: "SLES15.0SP1" ) )){
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

