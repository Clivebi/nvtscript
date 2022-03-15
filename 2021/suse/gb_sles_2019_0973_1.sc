if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0973.1" );
	script_cve_id( "CVE-2016-6153", "CVE-2018-20346", "CVE-2018-20506" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-23 01:15:00 +0000 (Sun, 23 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0973-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0973-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190973-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sqlite3' package(s) announced via the SUSE-SU-2019:0973-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sqlite3 fixes the following issues:

Security issues fixed:
CVE-2018-20506: Fixed an integer overflow when FTS3 extension is enabled
 (bsc#1131576).

CVE-2018-20346: Fixed a remote code execution vulnerability in FTS3
 (Magellan) (bsc#1119687).

CVE-2016-6153: Fixed incorrect permissions when creating temporary files
 (bsc#987394)." );
	script_tag( name: "affected", value: "'sqlite3' package(s) on SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0", rpm: "libsqlite3-0~3.8.3.1~2.7.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-32bit", rpm: "libsqlite3-0-32bit~3.8.3.1~2.7.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-debuginfo", rpm: "libsqlite3-0-debuginfo~3.8.3.1~2.7.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-debuginfo-32bit", rpm: "libsqlite3-0-debuginfo-32bit~3.8.3.1~2.7.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3", rpm: "sqlite3~3.8.3.1~2.7.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-debuginfo", rpm: "sqlite3-debuginfo~3.8.3.1~2.7.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-debugsource", rpm: "sqlite3-debugsource~3.8.3.1~2.7.1", rls: "SLES12.0" ) )){
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

