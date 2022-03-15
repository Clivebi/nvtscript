if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853949" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2021-29157", "CVE-2021-33515" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-18 06:15:00 +0000 (Sun, 18 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-13 03:04:57 +0000 (Tue, 13 Jul 2021)" );
	script_name( "openSUSE: Security Advisory for dovecot23 (openSUSE-SU-2021:2123-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2123-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/G567PZ5Z5XTMWM5HHQHCWSMCWQSOWCGA" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot23'
  package(s) announced via the openSUSE-SU-2021:2123-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dovecot23 fixes the following issues:

  - CVE-2021-29157: Local attacker can login as any user and access their
       emails (bsc#1187418)

  - CVE-2021-33515: Attacker can potentially steal user credentials and
       mails (bsc#1187419)" );
	script_tag( name: "affected", value: "'dovecot23' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "dovecot23", rpm: "dovecot23~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-mysql", rpm: "dovecot23-backend-mysql~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-mysql-debuginfo", rpm: "dovecot23-backend-mysql-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-pgsql", rpm: "dovecot23-backend-pgsql~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-pgsql-debuginfo", rpm: "dovecot23-backend-pgsql-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-sqlite", rpm: "dovecot23-backend-sqlite~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-sqlite-debuginfo", rpm: "dovecot23-backend-sqlite-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-debuginfo", rpm: "dovecot23-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-debugsource", rpm: "dovecot23-debugsource~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-devel", rpm: "dovecot23-devel~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts", rpm: "dovecot23-fts~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-debuginfo", rpm: "dovecot23-fts-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-lucene", rpm: "dovecot23-fts-lucene~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-lucene-debuginfo", rpm: "dovecot23-fts-lucene-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-solr", rpm: "dovecot23-fts-solr~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-solr-debuginfo", rpm: "dovecot23-fts-solr-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-squat", rpm: "dovecot23-fts-squat~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-squat-debuginfo", rpm: "dovecot23-fts-squat-debuginfo~2.3.11.3~55.1", rls: "openSUSELeap15.3" ) )){
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

