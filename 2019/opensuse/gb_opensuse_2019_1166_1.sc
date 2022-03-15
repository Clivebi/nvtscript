if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852408" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2019-9917" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-15 03:29:00 +0000 (Sat, 15 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-06 02:01:20 +0000 (Sat, 06 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for znc (openSUSE-SU-2019:1166-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.3|openSUSELeap15\\.0)" );
	script_xref( name: "openSUSE-SU", value: "2019:1166-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00037.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'znc'
  package(s) announced via the openSUSE-SU-2019:1166-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for znc to version 1.7.2 fixes the following issue:

  Security issue fixed:

  - CVE-2019-9917: Fixed an issue where due to invalid encoding znc was
  crashing (bsc#1130360).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1166=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1166=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2019-1166=1" );
	script_tag( name: "affected", value: "'znc' package(s) on openSUSE Leap 42.3, openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "znc", rpm: "znc~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-debuginfo", rpm: "znc-debuginfo~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-debugsource", rpm: "znc-debugsource~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-devel", rpm: "znc-devel~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-perl", rpm: "znc-perl~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-perl-debuginfo", rpm: "znc-perl-debuginfo~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-python3", rpm: "znc-python3~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-python3-debuginfo", rpm: "znc-python3-debuginfo~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-tcl", rpm: "znc-tcl~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-tcl-debuginfo", rpm: "znc-tcl-debuginfo~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-lang", rpm: "znc-lang~1.7.2~25.1", rls: "openSUSELeap42.3" ) )){
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
if(release == "openSUSELeap15.0"){
	if(!isnull( res = isrpmvuln( pkg: "znc", rpm: "znc~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-debuginfo", rpm: "znc-debuginfo~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-debugsource", rpm: "znc-debugsource~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-devel", rpm: "znc-devel~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-perl", rpm: "znc-perl~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-perl-debuginfo", rpm: "znc-perl-debuginfo~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-python3", rpm: "znc-python3~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-python3-debuginfo", rpm: "znc-python3-debuginfo~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-tcl", rpm: "znc-tcl~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-tcl-debuginfo", rpm: "znc-tcl-debuginfo~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "znc-lang", rpm: "znc-lang~1.7.2~lp150.25.1", rls: "openSUSELeap15.0" ) )){
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

