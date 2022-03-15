if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852625" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-13132" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-22 02:01:03 +0000 (Mon, 22 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for zeromq (openSUSE-SU-2019:1767-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1767-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00033.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zeromq'
  package(s) announced via the openSUSE-SU-2019:1767-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for zeromq fixes the following issues:

  - CVE-2019-13132: An unauthenticated remote attacker could have exploited
  a stack overflow vulnerability on a server that is supposed to be
  protected by encryption and authentication to potentially gain a remote
  code execution. (bsc#1140255)

  - Correctly mark license files as licence instead of documentation
  (bsc#1082318)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1767=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1767=1" );
	script_tag( name: "affected", value: "'zeromq' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libzmq5", rpm: "libzmq5~4.2.3~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libzmq5-debuginfo", rpm: "libzmq5-debuginfo~4.2.3~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zeromq-debugsource", rpm: "zeromq-debugsource~4.2.3~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zeromq-devel", rpm: "zeromq-devel~4.2.3~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zeromq-tools", rpm: "zeromq-tools~4.2.3~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "zeromq-tools-debuginfo", rpm: "zeromq-tools-debuginfo~4.2.3~lp150.2.15.1", rls: "openSUSELeap15.0" ) )){
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
