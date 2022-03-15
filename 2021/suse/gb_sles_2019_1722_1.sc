if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.1722.1" );
	script_cve_id( "CVE-2018-16428", "CVE-2018-16429", "CVE-2019-12450" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-31 21:15:00 +0000 (Wed, 31 Jul 2019)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:1722-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:1722-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20191722-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'glib2' package(s) announced via the SUSE-SU-2019:1722-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for glib2 provides the following fix:

Security issues fixed:
CVE-2019-12450: Fixed an improper file permission when copy operation
 takes place (bsc#1137001).

CVE-2018-16428: Avoid a null pointer dereference that could crash glib2
 users in markup processing (bnc#1107121).

CVE-2018-16429: Fixed out-of-bounds read vulnerability
 ing_markup_parse_context_parse() (bsc#1107116).

Non-security issues fixed:
Install dummy *-mimeapps.list files to prevent dead symlinks.
 (bsc#1061599)" );
	script_tag( name: "affected", value: "'glib2' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE CaaS Platform 3.0, SUSE Enterprise Storage 4, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Desktop 12-SP4, SUSE Linux Enterprise Desktop 12-SP5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP4, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "glib2-debugsource", rpm: "glib2-debugsource~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-lang", rpm: "glib2-lang~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools", rpm: "glib2-tools~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-debuginfo", rpm: "glib2-tools-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0", rpm: "libgio-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit", rpm: "libgio-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo", rpm: "libgio-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo-32bit", rpm: "libgio-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0", rpm: "libglib-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit", rpm: "libglib-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo", rpm: "libglib-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo-32bit", rpm: "libglib-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0", rpm: "libgmodule-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit", rpm: "libgmodule-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo", rpm: "libgmodule-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo-32bit", rpm: "libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0", rpm: "libgobject-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit", rpm: "libgobject-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo", rpm: "libgobject-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo-32bit", rpm: "libgobject-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0", rpm: "libgthread-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-32bit", rpm: "libgthread-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo", rpm: "libgthread-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo-32bit", rpm: "libgthread-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "glib2-debugsource", rpm: "glib2-debugsource~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-lang", rpm: "glib2-lang~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools", rpm: "glib2-tools~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-debuginfo", rpm: "glib2-tools-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0", rpm: "libgio-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit", rpm: "libgio-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo", rpm: "libgio-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo-32bit", rpm: "libgio-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0", rpm: "libglib-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit", rpm: "libglib-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo", rpm: "libglib-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo-32bit", rpm: "libglib-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0", rpm: "libgmodule-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit", rpm: "libgmodule-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo", rpm: "libgmodule-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo-32bit", rpm: "libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0", rpm: "libgobject-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit", rpm: "libgobject-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo", rpm: "libgobject-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo-32bit", rpm: "libgobject-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0", rpm: "libgthread-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-32bit", rpm: "libgthread-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo", rpm: "libgthread-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo-32bit", rpm: "libgthread-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "glib2-debugsource", rpm: "glib2-debugsource~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-lang", rpm: "glib2-lang~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools", rpm: "glib2-tools~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-debuginfo", rpm: "glib2-tools-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0", rpm: "libgio-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit", rpm: "libgio-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo", rpm: "libgio-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo-32bit", rpm: "libgio-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0", rpm: "libglib-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit", rpm: "libglib-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo", rpm: "libglib-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo-32bit", rpm: "libglib-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0", rpm: "libgmodule-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit", rpm: "libgmodule-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo", rpm: "libgmodule-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo-32bit", rpm: "libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0", rpm: "libgobject-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit", rpm: "libgobject-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo", rpm: "libgobject-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo-32bit", rpm: "libgobject-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0", rpm: "libgthread-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-32bit", rpm: "libgthread-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo", rpm: "libgthread-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo-32bit", rpm: "libgthread-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "glib2-debugsource", rpm: "glib2-debugsource~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-lang", rpm: "glib2-lang~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools", rpm: "glib2-tools~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "glib2-tools-debuginfo", rpm: "glib2-tools-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0", rpm: "libgio-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-32bit", rpm: "libgio-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo", rpm: "libgio-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgio-2_0-0-debuginfo-32bit", rpm: "libgio-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0", rpm: "libglib-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-32bit", rpm: "libglib-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo", rpm: "libglib-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libglib-2_0-0-debuginfo-32bit", rpm: "libglib-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0", rpm: "libgmodule-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-32bit", rpm: "libgmodule-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo", rpm: "libgmodule-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgmodule-2_0-0-debuginfo-32bit", rpm: "libgmodule-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0", rpm: "libgobject-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-32bit", rpm: "libgobject-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo", rpm: "libgobject-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgobject-2_0-0-debuginfo-32bit", rpm: "libgobject-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0", rpm: "libgthread-2_0-0~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-32bit", rpm: "libgthread-2_0-0-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo", rpm: "libgthread-2_0-0-debuginfo~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgthread-2_0-0-debuginfo-32bit", rpm: "libgthread-2_0-0-debuginfo-32bit~2.48.2~12.12.2", rls: "SLES12.0SP5" ) )){
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

