if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2605.1" );
	script_cve_id( "CVE-2021-2154", "CVE-2021-2166", "CVE-2021-27928" );
	script_tag( name: "creation_date", value: "2021-08-05 14:33:38 +0000 (Thu, 05 Aug 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2605-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2605-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212605-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2021:2605-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mariadb fixes the following issues:

Update to 10.2.39 (bsc#1182739)

CVE-2021-2166: DML unspecified vulnerability lead to complete DOS.
 (bsc#1185870)

CVE-2021-2154: DML unspecified vulnerability can lead to complete DOS.
 (bsc#1185872)

CVE-2021-27928: Fixed a remote code execution issue. (bsc#1183770)" );
	script_tag( name: "affected", value: "'mariadb' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP3." );
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libmariadbd-devel", rpm: "libmariadbd-devel~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadbd19", rpm: "libmariadbd19~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadbd19-debuginfo", rpm: "libmariadbd19-debuginfo~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client", rpm: "mariadb-client~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client-debuginfo", rpm: "mariadb-client-debuginfo~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debuginfo", rpm: "mariadb-debuginfo~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debugsource", rpm: "mariadb-debugsource~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-errormessages", rpm: "mariadb-errormessages~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools", rpm: "mariadb-tools~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools-debuginfo", rpm: "mariadb-tools-debuginfo~10.5.11~3.3.1", rls: "SLES15.0SP3" ) )){
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

