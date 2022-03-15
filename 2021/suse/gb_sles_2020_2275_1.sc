if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2275.1" );
	script_cve_id( "CVE-2019-20907" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2275-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2275-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202275-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python' package(s) announced via the SUSE-SU-2020:2275-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python fixes the following issues:

CVE-2019-20907: Avoid a possible infinite loop caused by specifically
 crafted tarballs (bsc#1174091)." );
	script_tag( name: "affected", value: "'python' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0", rpm: "libpython2_7-1_0~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-32bit", rpm: "libpython2_7-1_0-32bit~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo", rpm: "libpython2_7-1_0-debuginfo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpython2_7-1_0-debuginfo-32bit", rpm: "libpython2_7-1_0-debuginfo-32bit~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python", rpm: "python~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-32bit", rpm: "python-32bit~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base", rpm: "python-base~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-32bit", rpm: "python-base-32bit~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo", rpm: "python-base-debuginfo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debuginfo-32bit", rpm: "python-base-debuginfo-32bit~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-base-debugsource", rpm: "python-base-debugsource~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses", rpm: "python-curses~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-curses-debuginfo", rpm: "python-curses-debuginfo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo", rpm: "python-debuginfo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debuginfo-32bit", rpm: "python-debuginfo-32bit~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-debugsource", rpm: "python-debugsource~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-demo", rpm: "python-demo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc", rpm: "python-doc~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-doc-pdf", rpm: "python-doc-pdf~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm", rpm: "python-gdbm~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-gdbm-debuginfo", rpm: "python-gdbm-debuginfo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-idle", rpm: "python-idle~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk", rpm: "python-tk~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-tk-debuginfo", rpm: "python-tk-debuginfo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml", rpm: "python-xml~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-xml-debuginfo", rpm: "python-xml-debuginfo~2.7.17~28.48.1", rls: "SLES12.0SP5" ) )){
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

