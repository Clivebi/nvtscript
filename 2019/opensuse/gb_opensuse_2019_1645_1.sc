if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852594" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-8457" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)" );
	script_tag( name: "creation_date", value: "2019-06-28 02:00:51 +0000 (Fri, 28 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for sqlite3 (openSUSE-SU-2019:1645-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1645-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00074.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sqlite3'
  package(s) announced via the openSUSE-SU-2019:1645-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sqlite3 fixes the following issues:

  Security issue fixed:

  - CVE-2019-8457: Fixed a Heap out-of-bound read in rtreenode() when
  handling invalid rtree tables (bsc#1136976).

  This update was imported from the SUSE:SLE-12-SP1:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1645=1" );
	script_tag( name: "affected", value: "'sqlite3' package(s) on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0", rpm: "libsqlite3-0~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-debuginfo", rpm: "libsqlite3-0-debuginfo~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3", rpm: "sqlite3~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-debuginfo", rpm: "sqlite3-debuginfo~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-debugsource", rpm: "sqlite3-debugsource~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-devel", rpm: "sqlite3-devel~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-32bit", rpm: "libsqlite3-0-32bit~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-debuginfo-32bit", rpm: "libsqlite3-0-debuginfo-32bit~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-doc", rpm: "sqlite3-doc~3.8.10.2~11.10.1", rls: "openSUSELeap42.3" ) )){
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

