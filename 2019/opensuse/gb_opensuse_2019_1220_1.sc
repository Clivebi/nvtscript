if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852434" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2019-3814", "CVE-2019-7524" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-14 03:29:00 +0000 (Fri, 14 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-18 02:00:56 +0000 (Thu, 18 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for dovecot22 (openSUSE-SU-2019:1220-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1220-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00067.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot22'
  package(s) announced via the openSUSE-SU-2019:1220-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for dovecot22 fixes the following issues:

  Security issues fixed:

  - CVE-2019-7524: Fixed an improper file handling which could result in
  stack overflow allowing local root escalation (bsc#1130116).

  - CVE-2019-3814: Fixed a vulnerability related to SSL client certificate
  authentication (bsc#1123022).

  Other issue fixed:

  - Fixed handling of command continuation (bsc#1111789).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1220=1" );
	script_tag( name: "affected", value: "'dovecot22' package(s) on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "dovecot22", rpm: "dovecot22~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql", rpm: "dovecot22-backend-mysql~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-mysql-debuginfo", rpm: "dovecot22-backend-mysql-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql", rpm: "dovecot22-backend-pgsql~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-pgsql-debuginfo", rpm: "dovecot22-backend-pgsql-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite", rpm: "dovecot22-backend-sqlite~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-backend-sqlite-debuginfo", rpm: "dovecot22-backend-sqlite-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debuginfo", rpm: "dovecot22-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-debugsource", rpm: "dovecot22-debugsource~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-devel", rpm: "dovecot22-devel~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts", rpm: "dovecot22-fts~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts-debuginfo", rpm: "dovecot22-fts-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts-lucene", rpm: "dovecot22-fts-lucene~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts-lucene-debuginfo", rpm: "dovecot22-fts-lucene-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts-solr", rpm: "dovecot22-fts-solr~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts-solr-debuginfo", rpm: "dovecot22-fts-solr-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts-squat", rpm: "dovecot22-fts-squat~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dovecot22-fts-squat-debuginfo", rpm: "dovecot22-fts-squat-debuginfo~2.2.31~2.12.1", rls: "openSUSELeap42.3" ) )){
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

