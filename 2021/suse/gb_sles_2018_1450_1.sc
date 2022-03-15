if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1450.1" );
	script_cve_id( "CVE-2015-3152", "CVE-2017-10788", "CVE-2017-10789" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 18:24:00 +0000 (Wed, 12 Jul 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1450-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1450-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181450-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl-DBD-mysql' package(s) announced via the SUSE-SU-2018:1450-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for perl-DBD-mysql fixes the following issues:
- CVE-2017-10789: The DBD::mysql module when with mysql_ssl=1 setting
 enabled, means that SSL is optional (even though this setting's
 documentation has a \\'your communication with the server will be
 encrypted\\' statement), which could lead man-in-the-middle attackers to
 spoof servers via a cleartext-downgrade attack, a related issue to
 CVE-2015-3152. (bsc#1047059)
- CVE-2017-10788: The DBD::mysql module through 4.043 for Perl allows
 remote attackers to cause a denial of service (use-after-free and
 application crash) or possibly have unspecified other impact by
 triggering (1) certain error responses from a MySQL server or (2) a loss
 of a network connection to a MySQL server. The use-after-free defect was
 introduced by relying on incorrect Oracle mysql_stmt_close documentation
 and code examples. (bsc#1047095)" );
	script_tag( name: "affected", value: "'perl-DBD-mysql' package(s) on SUSE Linux Enterprise Server 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "perl-DBD-mysql", rpm: "perl-DBD-mysql~4.021~12.5.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-DBD-mysql-debuginfo", rpm: "perl-DBD-mysql-debuginfo~4.021~12.5.2", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-DBD-mysql-debugsource", rpm: "perl-DBD-mysql-debugsource~4.021~12.5.2", rls: "SLES12.0SP3" ) )){
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

