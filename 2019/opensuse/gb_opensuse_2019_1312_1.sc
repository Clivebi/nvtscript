if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852466" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-10691" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-03 02:00:40 +0000 (Fri, 03 May 2019)" );
	script_name( "openSUSE: Security Advisory for dovecot23 (openSUSE-SU-2019:1312-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1312-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00000.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot23'
  package(s) announced via the openSUSE-SU-2019:1312-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dovecot23 fixes the following issues:

  Security issue fixed:

  - CVE-2019-10691: Fixed a denial of service via reachable assertion when
  processing invalid UTF-8 characters (bsc#1132501).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1312=1" );
	script_tag( name: "affected", value: "'dovecot23' package(s) on openSUSE Leap 15.0." );
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "dovecot23", rpm: "dovecot23~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-mysql", rpm: "dovecot23-backend-mysql~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-mysql-debuginfo", rpm: "dovecot23-backend-mysql-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-pgsql", rpm: "dovecot23-backend-pgsql~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-pgsql-debuginfo", rpm: "dovecot23-backend-pgsql-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-sqlite", rpm: "dovecot23-backend-sqlite~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-backend-sqlite-debuginfo", rpm: "dovecot23-backend-sqlite-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-debuginfo", rpm: "dovecot23-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-debugsource", rpm: "dovecot23-debugsource~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-devel", rpm: "dovecot23-devel~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts", rpm: "dovecot23-fts~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-debuginfo", rpm: "dovecot23-fts-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-lucene", rpm: "dovecot23-fts-lucene~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-lucene-debuginfo", rpm: "dovecot23-fts-lucene-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-solr", rpm: "dovecot23-fts-solr~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-solr-debuginfo", rpm: "dovecot23-fts-solr-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-squat", rpm: "dovecot23-fts-squat~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot23-fts-squat-debuginfo", rpm: "dovecot23-fts-squat-debuginfo~2.3.3~lp150.11.1", rls: "openSUSELeap15.0" ) )){
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

