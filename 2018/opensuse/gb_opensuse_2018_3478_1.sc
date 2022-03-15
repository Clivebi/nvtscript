if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851985" );
	script_version( "2021-06-25T11:00:33+0000" );
	script_cve_id( "CVE-2016-9843", "CVE-2018-3133", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3174", "CVE-2018-3247", "CVE-2018-3251", "CVE-2018-3276", "CVE-2018-3278", "CVE-2018-3282" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 11:00:33 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 21:15:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:26:39 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for mysql-community-server (openSUSE-SU-2018:3478-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2018:3478-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00072.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mysql-community-server'
  package(s) announced via the openSUSE-SU-2018:3478-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MySQL Community Server was updated to 5.6.42, fixing bugs and security
  issues:

  Fixed CVEs:

  - CVE-2016-9843 [boo#1013882], CVE-2018-3143 [boo#1112421],

  - CVE-2018-3156 [boo#1112417], CVE-2018-3251 [boo#1112397],

  - CVE-2018-3133 [boo#1112369], CVE-2018-3247 [boo#1112398],

  - CVE-2018-3174 [boo#1112368], CVE-2018-3276 [boo#1112393],

  - CVE-2018-3278 [boo#1112390], CVE-2018-3282 [boo#1112432],

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1284=1" );
	script_tag( name: "affected", value: "mysql-community-server on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18", rpm: "libmysql56client18~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-debuginfo", rpm: "libmysql56client18-debuginfo~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client_r18", rpm: "libmysql56client_r18~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server", rpm: "mysql-community-server~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-bench", rpm: "mysql-community-server-bench~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-bench-debuginfo", rpm: "mysql-community-server-bench-debuginfo~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-client", rpm: "mysql-community-server-client~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-client-debuginfo", rpm: "mysql-community-server-client-debuginfo~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-debuginfo", rpm: "mysql-community-server-debuginfo~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-debugsource", rpm: "mysql-community-server-debugsource~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-test", rpm: "mysql-community-server-test~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-test-debuginfo", rpm: "mysql-community-server-test-debuginfo~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-tools", rpm: "mysql-community-server-tools~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-tools-debuginfo", rpm: "mysql-community-server-tools-debuginfo~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mysql-community-server-errormessages", rpm: "mysql-community-server-errormessages~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-32bit", rpm: "libmysql56client18-32bit~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client18-debuginfo-32bit", rpm: "libmysql56client18-debuginfo-32bit~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmysql56client_r18-32bit", rpm: "libmysql56client_r18-32bit~5.6.42~42.1", rls: "openSUSELeap42.3" ) )){
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

