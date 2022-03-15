if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853131" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2020-11651", "CVE-2020-11652" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-20 01:17:00 +0000 (Thu, 20 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-05-01 03:01:53 +0000 (Fri, 01 May 2020)" );
	script_name( "openSUSE: Security Advisory for salt (openSUSE-SU-2020:0564-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0564-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00047.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'salt'
  package(s) announced via the openSUSE-SU-2020:0564-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for salt fixes the following issues:

  - Fix CVE-2020-11651 and CVE-2020-11652 (bsc#1170595)

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-564=1" );
	script_tag( name: "affected", value: "'salt' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "python2-salt", rpm: "python2-salt~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-salt", rpm: "python3-salt~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt", rpm: "salt~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-api", rpm: "salt-api~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-cloud", rpm: "salt-cloud~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-doc", rpm: "salt-doc~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-master", rpm: "salt-master~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-minion", rpm: "salt-minion~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-proxy", rpm: "salt-proxy~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-ssh", rpm: "salt-ssh~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-standalone-formulas-configuration", rpm: "salt-standalone-formulas-configuration~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-syndic", rpm: "salt-syndic~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-bash-completion", rpm: "salt-bash-completion~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-fish-completion", rpm: "salt-fish-completion~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "salt-zsh-completion", rpm: "salt-zsh-completion~2019.2.0~lp151.5.15.1", rls: "openSUSELeap15.1" ) )){
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

