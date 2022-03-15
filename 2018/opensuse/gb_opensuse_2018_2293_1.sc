if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851845" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-10 06:00:24 +0200 (Fri, 10 Aug 2018)" );
	script_cve_id( "CVE-2018-0739", "CVE-2018-2767", "CVE-2018-3058", "CVE-2018-3062", "CVE-2018-3064", "CVE-2018-3066", "CVE-2018-3070", "CVE-2018-3081" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for mysql-community-server (openSUSE-SU-2018:2293-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-community-server'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for mysql-community-server to version 5.6.41 fixes the
  following issues:

  Security vulnerabilities fixed:

  - CVE-2018-3064: Fixed an easily exploitable vulnerability that allowed a
  low privileged attacker with network access via multiple protocols to
  compromise the MySQL Server. Successful attacks of this vulnerability
  can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server as well as unauthorized
  update, insert or delete access to some of MySQL Server accessible data.
  (bsc#1103342)

  - CVE-2018-3070: Fixed an easily exploitable vulnerability that allowed a
  low privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Server. (bsc#1101679)

  - CVE-2018-0739: Fixed a stack exhaustion in case of recursively
  constructed ASN.1 types. (boo#1087102)

  - CVE-2018-3062: Fixed a difficult to exploit vulnerability that allowed
  low privileged attacker with network access via memcached to compromise
  MySQL Server. Successful attacks of this vulnerability can result in
  unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Server. (bsc#1103344)

  - CVE-2018-3081: Fixed a difficult to exploit vulnerability that allowed
  high privileged attacker with network access via multiple protocols to
  compromise MySQL Client. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Client as well as unauthorized update,
  insert or delete access to some of MySQL Client accessible data.
  (bsc#1101680)

  - CVE-2018-3058: Fixed an easily exploitable vulnerability that allowed
  low privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized update, insert or delete access to some of MySQL
  Server accessible data. (bsc#1101676)

  - CVE-2018-3066: Fixed a difficult to exploit vulnerability allowed high
  privileged attacker with network access via multiple protocols to
  compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized update, insert or delete access to some of MySQL
  Server accessible data as well as unauthorized read access to a subset
  of MySQL Server accessible data. (bsc#1101678)

  - CVE-2018-2767: Fixed a difficult to exploit  ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "mysql-community-server on openSUSE Leap 42.3" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2018:2293-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00039.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18", rpm: "libmysql56client18~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-debuginfo", rpm: "libmysql56client18-debuginfo~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client_r18", rpm: "libmysql56client_r18~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server", rpm: "mysql-community-server~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-bench", rpm: "mysql-community-server-bench~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-bench-debuginfo", rpm: "mysql-community-server-bench-debuginfo~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-client", rpm: "mysql-community-server-client~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-client-debuginfo", rpm: "mysql-community-server-client-debuginfo~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-debuginfo", rpm: "mysql-community-server-debuginfo~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-debugsource", rpm: "mysql-community-server-debugsource~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-test", rpm: "mysql-community-server-test~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-test-debuginfo", rpm: "mysql-community-server-test-debuginfo~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-tools", rpm: "mysql-community-server-tools~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-tools-debuginfo", rpm: "mysql-community-server-tools-debuginfo~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-32bit", rpm: "libmysql56client18-32bit~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-debuginfo-32bit", rpm: "libmysql56client18-debuginfo-32bit~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client_r18-32bit", rpm: "libmysql56client_r18-32bit~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-errormessages", rpm: "mysql-community-server-errormessages~5.6.41~39.1", rls: "openSUSELeap42.3" ) )){
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

