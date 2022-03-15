if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2439.1" );
	script_cve_id( "CVE-2021-22922", "CVE-2021-22923", "CVE-2021-22924", "CVE-2021-22925" );
	script_tag( name: "creation_date", value: "2021-07-22 02:21:52 +0000 (Thu, 22 Jul 2021)" );
	script_version( "2021-09-12T02:20:55+0000" );
	script_tag( name: "last_modification", value: "2021-09-12 02:20:55 +0000 (Sun, 12 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-02 09:15:00 +0000 (Thu, 02 Sep 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2439-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2|SLES15\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2439-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212439-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2021:2439-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for curl fixes the following issues:

CVE-2021-22925: TELNET stack contents disclosure again. (bsc#1188220)

CVE-2021-22924: Bad connection reuse due to flawed path name checks.
 (bsc#1188219)

CVE-2021-22923: Insufficiently Protected Credentials. (bsc#1188218)

CVE-2021-22922: Wrong content via metalink not discarded. (bsc#1188217)" );
	script_tag( name: "affected", value: "'curl' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE MicroOS 5.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debuginfo", rpm: "curl-debuginfo~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debugsource", rpm: "curl-debugsource~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel", rpm: "libcurl-devel~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit", rpm: "libcurl4-32bit~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit-debuginfo", rpm: "libcurl4-32bit-debuginfo~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4", rpm: "libcurl4~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-debuginfo", rpm: "libcurl4-debuginfo~7.66.0~4.22.1", rls: "SLES15.0SP2" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "curl", rpm: "curl~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debuginfo", rpm: "curl-debuginfo~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "curl-debugsource", rpm: "curl-debugsource~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl-devel", rpm: "libcurl-devel~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit", rpm: "libcurl4-32bit~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-32bit-debuginfo", rpm: "libcurl4-32bit-debuginfo~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4", rpm: "libcurl4~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-debuginfo", rpm: "libcurl4-debuginfo~7.66.0~4.22.1", rls: "SLES15.0SP3" ) )){
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

