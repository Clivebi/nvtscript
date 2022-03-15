if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852491" );
	script_version( "2021-09-07T13:01:38+0000" );
	script_cve_id( "CVE-2019-9936", "CVE-2019-9937" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 13:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-23 01:15:00 +0000 (Sun, 23 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-11 02:01:00 +0000 (Sat, 11 May 2019)" );
	script_name( "openSUSE: Security Advisory for sqlite3 (openSUSE-SU-2019:1372-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1372-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00026.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sqlite3'
  package(s) announced via the openSUSE-SU-2019:1372-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sqlite3 to version 3.28.0 fixes the following issues:

  Security issues fixed:

  - CVE-2019-9936: Fixed a heap-based buffer over-read, when running fts5
  prefix queries inside transaction (bsc#1130326).

  - CVE-2019-9937: Fixed a denial of service related to interleaving reads
  and writes in a single transaction with an fts5 virtual table
  (bsc#1130325).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1372=1" );
	script_tag( name: "affected", value: "'sqlite3' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0", rpm: "libsqlite3-0~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-debuginfo", rpm: "libsqlite3-0-debuginfo~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3", rpm: "sqlite3~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-debuginfo", rpm: "sqlite3-debuginfo~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-debugsource", rpm: "sqlite3-debugsource~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-devel", rpm: "sqlite3-devel~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-32bit", rpm: "libsqlite3-0-32bit~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libsqlite3-0-32bit-debuginfo", rpm: "libsqlite3-0-32bit-debuginfo~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqlite3-doc", rpm: "sqlite3-doc~3.28.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

