if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853153" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2020-12050" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-27 16:15:00 +0000 (Wed, 27 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-12 03:03:41 +0000 (Tue, 12 May 2020)" );
	script_name( "openSUSE: Security Advisory for sqliteodbc (openSUSE-SU-2020:0628-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0628-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00026.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sqliteodbc'
  package(s) announced via the openSUSE-SU-2020:0628-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for sqliteodbc fixes the following issues:

  Security issue fixed:

  - CVE-2020-12050: Fixed a privilege escalation vulnerability (boo#1171041).

  Non-security issues fixed:

  - Update to version 0.9996

  * update to SQLite 3.22.0

  * fixes in handling DDL in SQLExecDirect() et.al., thanks Andre Mikulec
  for testing

  * cleanup utf8/unicode conversion functions


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-628=1" );
	script_tag( name: "affected", value: "'sqliteodbc' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "sqliteodbc", rpm: "sqliteodbc~0.9996~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqliteodbc-debuginfo", rpm: "sqliteodbc-debuginfo~0.9996~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqliteodbc-debugsource", rpm: "sqliteodbc-debugsource~0.9996~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "sqliteodbc-doc", rpm: "sqliteodbc-doc~0.9996~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

