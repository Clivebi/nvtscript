if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0265.1" );
	script_cve_id( "CVE-2019-5188" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:09 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-12 14:09:00 +0000 (Tue, 12 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0265-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0|SLES15\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0265-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200265-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'e2fsprogs' package(s) announced via the SUSE-SU-2020:0265-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for e2fsprogs fixes the following issues:
CVE-2019-5188: Fixed a code execution vulnerability in the directory
 rehashing functionality (bsc#1160571)." );
	script_tag( name: "affected", value: "'e2fsprogs' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs", rpm: "e2fsprogs~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-32bit-debuginfo", rpm: "e2fsprogs-32bit-debuginfo~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-debuginfo", rpm: "e2fsprogs-debuginfo~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-debugsource", rpm: "e2fsprogs-debugsource~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-devel", rpm: "e2fsprogs-devel~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err-devel", rpm: "libcom_err-devel~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err-devel-static", rpm: "libcom_err-devel-static~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2", rpm: "libcom_err2~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-32bit", rpm: "libcom_err2-32bit~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-32bit-debuginfo", rpm: "libcom_err2-32bit-debuginfo~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-debuginfo", rpm: "libcom_err2-debuginfo~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs-devel", rpm: "libext2fs-devel~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs-devel-static", rpm: "libext2fs-devel-static~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2", rpm: "libext2fs2~1.43.8~4.17.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2-debuginfo", rpm: "libext2fs2-debuginfo~1.43.8~4.17.1", rls: "SLES15.0" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs", rpm: "e2fsprogs~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-32bit-debuginfo", rpm: "e2fsprogs-32bit-debuginfo~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-debuginfo", rpm: "e2fsprogs-debuginfo~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-debugsource", rpm: "e2fsprogs-debugsource~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "e2fsprogs-devel", rpm: "e2fsprogs-devel~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err-devel", rpm: "libcom_err-devel~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err-devel-static", rpm: "libcom_err-devel-static~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2", rpm: "libcom_err2~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-32bit", rpm: "libcom_err2-32bit~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-32bit-debuginfo", rpm: "libcom_err2-32bit-debuginfo~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcom_err2-debuginfo", rpm: "libcom_err2-debuginfo~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs-devel", rpm: "libext2fs-devel~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs-devel-static", rpm: "libext2fs-devel-static~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2", rpm: "libext2fs2~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libext2fs2-debuginfo", rpm: "libext2fs2-debuginfo~1.43.8~4.17.1", rls: "SLES15.0SP1" ) )){
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

