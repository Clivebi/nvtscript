if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852654" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-2614", "CVE-2019-2627", "CVE-2019-2628" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-16 02:01:06 +0000 (Fri, 16 Aug 2019)" );
	script_name( "openSUSE: Security Advisory for mariadb, mariadb-connector-c (openSUSE-SU-2019:1915-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1915-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00032.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mariadb, mariadb-connector-c'
  package(s) announced via the openSUSE-SU-2019:1915-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mariadb and mariadb-connector-c fixes the following issues:

  mariadb:

  - Update to version 10.2.25 (bsc#1136035)

  - CVE-2019-2628: Fixed a remote denial of service by a privileged
  attacker (bsc#1136035).

  - CVE-2019-2627: Fixed another remote denial of service by a privileged
  attacker (bsc#1136035).

  - CVE-2019-2614: Fixed a potential remote denial of service by an
  privileged attacker (bsc#1136035).

  - Fixed reading options for multiple instances if my${INSTANCE}.cnf is
  used (bsc#1132666)

  mariadb-connector-c:

  - Update to version 3.1.2 (bsc#1136035)

  - Moved libmariadb.pc from /usr/lib/pkgconfig to /usr/lib64/pkgconfig for
  x86_64 (bsc#1126088)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1915=1" );
	script_tag( name: "affected", value: "'mariadb, ' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmariadb-devel", rpm: "libmariadb-devel~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb-devel-debuginfo", rpm: "libmariadb-devel-debuginfo~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb3", rpm: "libmariadb3~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb3-debuginfo", rpm: "libmariadb3-debuginfo~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb_plugins", rpm: "libmariadb_plugins~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb_plugins-debuginfo", rpm: "libmariadb_plugins-debuginfo~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadbprivate", rpm: "libmariadbprivate~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadbprivate-debuginfo", rpm: "libmariadbprivate-debuginfo~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld-devel", rpm: "libmysqld-devel~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld19", rpm: "libmysqld19~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysqld19-debuginfo", rpm: "libmysqld19-debuginfo~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb", rpm: "mariadb~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench", rpm: "mariadb-bench~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-bench-debuginfo", rpm: "mariadb-bench-debuginfo~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client", rpm: "mariadb-client~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-client-debuginfo", rpm: "mariadb-client-debuginfo~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-connector-c-debugsource", rpm: "mariadb-connector-c-debugsource~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debuginfo", rpm: "mariadb-debuginfo~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-debugsource", rpm: "mariadb-debugsource~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-galera", rpm: "mariadb-galera~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test", rpm: "mariadb-test~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-test-debuginfo", rpm: "mariadb-test-debuginfo~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools", rpm: "mariadb-tools~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-tools-debuginfo", rpm: "mariadb-tools-debuginfo~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-errormessages", rpm: "mariadb-errormessages~10.2.25~lp150.2.13.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb3-32bit", rpm: "libmariadb3-32bit~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb3-32bit-debuginfo", rpm: "libmariadb3-32bit-debuginfo~3.1.2~lp150.10.1", rls: "openSUSELeap15.0" ) )){
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

