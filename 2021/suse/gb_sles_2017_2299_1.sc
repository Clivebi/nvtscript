if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.2299.1" );
	script_cve_id( "CVE-2016-9063", "CVE-2017-9233" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-07-30 18:31:00 +0000 (Mon, 30 Jul 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:2299-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:2299-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20172299-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'expat' package(s) announced via the SUSE-SU-2017:2299-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for expat fixes the following issues:
- CVE-2016-9063: Possible integer overflow to fix inside XML_Parse leading
 to unexpected behaviour (bsc#1047240)
- CVE-2017-9233: External Entity Vulnerability could lead to denial of
 service (bsc#1047236)" );
	script_tag( name: "affected", value: "'expat' package(s) on OpenStack Cloud Magnum Orchestration 7, SUSE Container as a Service Platform ALL, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Software Development Kit 12-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "expat", rpm: "expat~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo", rpm: "expat-debuginfo~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo-32bit", rpm: "expat-debuginfo-32bit~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debugsource", rpm: "expat-debugsource~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1", rpm: "libexpat1~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-32bit", rpm: "libexpat1-32bit~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo", rpm: "libexpat1-debuginfo~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo-32bit", rpm: "libexpat1-debuginfo-32bit~2.1.0~21.3.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "expat", rpm: "expat~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo", rpm: "expat-debuginfo~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo-32bit", rpm: "expat-debuginfo-32bit~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debugsource", rpm: "expat-debugsource~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1", rpm: "libexpat1~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-32bit", rpm: "libexpat1-32bit~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo", rpm: "libexpat1-debuginfo~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libexpat1-debuginfo-32bit", rpm: "libexpat1-debuginfo-32bit~2.1.0~21.3.1", rls: "SLES12.0SP3" ) )){
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
