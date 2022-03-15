if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2930.1" );
	script_cve_id( "CVE-2019-18218" );
	script_tag( name: "creation_date", value: "2021-09-03 02:21:39 +0000 (Fri, 03 Sep 2021)" );
	script_version( "2021-09-03T02:21:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 02:21:39 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-15 15:15:00 +0000 (Thu, 15 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2930-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2930-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212930-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'file' package(s) announced via the SUSE-SU-2021:2930-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for file fixes the following issues:

CVE-2019-18218: Fixed heap-based buffer overflow in
 cdf_read_property_info in cdf.c (bsc#1154661)." );
	script_tag( name: "affected", value: "'file' package(s) on HPE Helion Openstack 8, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9." );
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
	if(!isnull( res = isrpmvuln( pkg: "file", rpm: "file~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debuginfo", rpm: "file-debuginfo~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debugsource", rpm: "file-debugsource~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-magic", rpm: "file-magic~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-32bit", rpm: "libmagic1-32bit~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1", rpm: "libmagic1~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo-32bit", rpm: "libmagic1-debuginfo-32bit~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo", rpm: "libmagic1-debuginfo~5.22~10.21.1", rls: "SLES12.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "file", rpm: "file~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debuginfo", rpm: "file-debuginfo~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debugsource", rpm: "file-debugsource~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-magic", rpm: "file-magic~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-32bit", rpm: "libmagic1-32bit~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1", rpm: "libmagic1~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo-32bit", rpm: "libmagic1-debuginfo-32bit~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo", rpm: "libmagic1-debuginfo~5.22~10.21.1", rls: "SLES12.0SP3" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "file", rpm: "file~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debuginfo", rpm: "file-debuginfo~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debugsource", rpm: "file-debugsource~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-magic", rpm: "file-magic~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-32bit", rpm: "libmagic1-32bit~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1", rpm: "libmagic1~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo-32bit", rpm: "libmagic1-debuginfo-32bit~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo", rpm: "libmagic1-debuginfo~5.22~10.21.1", rls: "SLES12.0SP4" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "file", rpm: "file~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debuginfo", rpm: "file-debuginfo~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-debugsource", rpm: "file-debugsource~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "file-magic", rpm: "file-magic~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-32bit", rpm: "libmagic1-32bit~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1", rpm: "libmagic1~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo-32bit", rpm: "libmagic1-debuginfo-32bit~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmagic1-debuginfo", rpm: "libmagic1-debuginfo~5.22~10.21.1", rls: "SLES12.0SP5" ) )){
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

