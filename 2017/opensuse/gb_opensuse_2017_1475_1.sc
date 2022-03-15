if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851562" );
	script_version( "2021-09-15T13:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 13:01:45 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-03 06:54:23 +0200 (Sat, 03 Jun 2017)" );
	script_cve_id( "CVE-2017-3302", "CVE-2017-3313" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for mariadb (openSUSE-SU-2017:1475-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mariadb fixes the following
  issues: - update to MariaDB 10.0.30 GA * notable changes: * XtraDB updated to
  5.6.35-80.0 * TokuDB updated to 5.6.35-80.0 * PCRE updated to 8.40 * MDEV-11027:
  better InnoDB crash recovery progress reporting * MDEV-11520: improvements to
  how InnoDB data files are extended * Improvements to InnoDB startup/shutdown to
  make it more robust * MDEV-11233: fix for FULLTEXT index crash * MDEV-6143:
  MariaDB Linux binary tarballs will now always untar to directories that match
  their filename * release notes and changelog are available in the linked references.

  * fixes the following CVEs: CVE-2017-3313: unspecified vulnerability affecting
  the MyISAM component [bsc#1020890] CVE-2017-3302: Use after free in
  libmysqlclient.so [bsc#1022428] - set the default umask to 077 in
  mysql-systemd-helper [bsc#1020976] - [bsc#1034911] - tracker bug * fixes also
  [bsc#1020868] This update for mariadb fixes permissions for /var/run/mysql in
  mysql-systemd-helper that were incorrectly set to 700 instead of 755 due to
  umask. This prevented non-root users from connecting to the database. This
  update was imported from the SUSE:SLE-12-SP1:Update update project." );
	script_tag( name: "affected", value: "mariadb on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:1475-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
	script_xref( name: "URL", value: "https://kb.askmonty.org/en/mariadb-10030-release-notes" );
	script_xref( name: "URL", value: "https://kb.askmonty.org/en/mariadb-10030-changelog" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient-devel", rpm: "libmysqlclient-devel~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18", rpm: "libmysqlclient18~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo", rpm: "libmysqlclient18-debuginfo~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient_r18", rpm: "libmysqlclient_r18~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld-devel", rpm: "libmysqld-devel~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld18", rpm: "libmysqld18~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld18-debuginfo", rpm: "libmysqld18-debuginfo~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench", rpm: "mariadb-bench~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench-debuginfo", rpm: "mariadb-bench-debuginfo~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client", rpm: "mariadb-client~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client-debuginfo", rpm: "mariadb-client-debuginfo~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debuginfo", rpm: "mariadb-debuginfo~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debugsource", rpm: "mariadb-debugsource~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-errormessages", rpm: "mariadb-errormessages~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test", rpm: "mariadb-test~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test-debuginfo", rpm: "mariadb-test-debuginfo~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools", rpm: "mariadb-tools~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools-debuginfo", rpm: "mariadb-tools-debuginfo~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-32bit", rpm: "libmysqlclient18-32bit~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient18-debuginfo-32bit", rpm: "libmysqlclient18-debuginfo-32bit~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqlclient_r18-32bit", rpm: "libmysqlclient_r18-32bit~10.0.30~20.4.1", rls: "openSUSELeap42.2" ) )){
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

