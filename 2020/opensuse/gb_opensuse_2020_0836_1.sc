if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853219" );
	script_version( "2020-06-24T03:42:18+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-24 03:42:18 +0000 (Wed, 24 Jun 2020)" );
	script_tag( name: "creation_date", value: "2020-06-20 03:00:44 +0000 (Sat, 20 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for rmt-server (openSUSE-SU-2020:0836-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0836-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00039.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rmt-server'
  package(s) announced via the openSUSE-SU-2020:0836-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rmt-server to version 2.5.7 fixes the following issues:

  - Fixed a local denial of service (bsc#1165548).

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-836=1" );
	script_tag( name: "affected", value: "'rmt-server' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "rmt-server", rpm: "rmt-server~2.5.7~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rmt-server-config", rpm: "rmt-server-config~2.5.7~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rmt-server-debuginfo", rpm: "rmt-server-debuginfo~2.5.7~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rmt-server-debugsource", rpm: "rmt-server-debugsource~2.5.7~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mt-server-pubcloud", rpm: "mt-server-pubcloud~2.5.7~lp151.2.15.1", rls: "openSUSELeap15.1" ) )){
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

