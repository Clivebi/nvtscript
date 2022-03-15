if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852690" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-12855" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-14 03:15:00 +0000 (Wed, 14 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-09-06 02:00:55 +0000 (Fri, 06 Sep 2019)" );
	script_name( "openSUSE: Security Advisory for python-Twisted (openSUSE-SU-2019:2068-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2068-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00013.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-Twisted'
  package(s) announced via the openSUSE-SU-2019:2068-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for python-Twisted fixes the following issues:

  Security issue fixed:

  - CVE-2019-12855: Fixed TLS certificate verification to protecting against
  MITM attacks (bsc#1138461).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2068=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2068=1" );
	script_tag( name: "affected", value: "'python-Twisted' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "python-Twisted-debuginfo", rpm: "python-Twisted-debuginfo~17.9.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-Twisted-debugsource", rpm: "python-Twisted-debugsource~17.9.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-Twisted-doc", rpm: "python-Twisted-doc~17.9.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-Twisted", rpm: "python2-Twisted~17.9.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python2-Twisted-debuginfo", rpm: "python2-Twisted-debuginfo~17.9.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-Twisted", rpm: "python3-Twisted~17.9.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-Twisted-debuginfo", rpm: "python3-Twisted-debuginfo~17.9.0~lp150.2.6.1", rls: "openSUSELeap15.0" ) )){
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

