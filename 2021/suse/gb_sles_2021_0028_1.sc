if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.0028.1" );
	script_cve_id( "CVE-2020-12100", "CVE-2020-12673", "CVE-2020-12674", "CVE-2020-24386", "CVE-2020-25275" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:46 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-06 23:15:00 +0000 (Wed, 06 Jan 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:0028-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:0028-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20210028-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot23' package(s) announced via the SUSE-SU-2021:0028-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dovecot23 fixes the following issues:

Security issues fixed:

CVE-2020-12100: Fixed a resource exhaustion caused by deeply nested MIME
 parts (bsc#1174920).

CVE-2020-12673: Fixed an improper implementation of NTLM that did not
 check the message buffer size (bsc#1174922).

CVE-2020-12674: Fixed an improper implementation of the RPA mechanism
 (bsc#1174923).

CVE-2020-24386: Fixed an issue with IMAP hibernation that allowed users
 to access other users' emails (bsc#1180405).

CVE-2020-25275: Fixed a crash when the 10000th MIME part was
 message/rfc822 (bsc#1180406).

Non-security issues fixed:

Pigeonhole was updated to version 0.5.11.

Dovecot was updated to version 2.3.11.3." );
	script_tag( name: "affected", value: "'dovecot23' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP2." );
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
	if(!isnull( res = isrpmvuln( pkg: "dovecot23", rpm: "dovecot23~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-mysql", rpm: "dovecot23-backend-mysql~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-mysql-debuginfo", rpm: "dovecot23-backend-mysql-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-pgsql", rpm: "dovecot23-backend-pgsql~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-pgsql-debuginfo", rpm: "dovecot23-backend-pgsql-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-sqlite", rpm: "dovecot23-backend-sqlite~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-sqlite-debuginfo", rpm: "dovecot23-backend-sqlite-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-debuginfo", rpm: "dovecot23-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-debugsource", rpm: "dovecot23-debugsource~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-devel", rpm: "dovecot23-devel~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts", rpm: "dovecot23-fts~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-debuginfo", rpm: "dovecot23-fts-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-lucene", rpm: "dovecot23-fts-lucene~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-lucene-debuginfo", rpm: "dovecot23-fts-lucene-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-solr", rpm: "dovecot23-fts-solr~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-solr-debuginfo", rpm: "dovecot23-fts-solr-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-squat", rpm: "dovecot23-fts-squat~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-squat-debuginfo", rpm: "dovecot23-fts-squat-debuginfo~2.3.11.3~17.5.1", rls: "SLES15.0SP2" ) )){
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

