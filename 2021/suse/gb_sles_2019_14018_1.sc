if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.14018.1" );
	script_cve_id( "CVE-2019-9636", "CVE-2019-9948" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:26 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-29 14:15:00 +0000 (Thu, 29 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:14018-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:14018-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201914018-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python' package(s) announced via the SUSE-SU-2019:14018-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python fixes the following issues:

Security issues fixed:
CVE-2019-9948: Fixed a 'file:' blacklist bypass in URIs by using the
 'local-file:' scheme instead (bsc#1130847).

CVE-2019-9636: Fixed an information disclosure because of incorrect
 handling of Unicode encoding during NFKC normalization (bsc#1129346)." );
	script_tag( name: "affected", value: "'python' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libpython2_6-1_0", rpm: "libpython2_6-1_0~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_6-1_0-32bit", rpm: "libpython2_6-1_0-32bit~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.6~8.40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.6~8.40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.6.9~40.24.1", rls: "SLES11.0SP4" ) )){
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

