if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853226" );
	script_version( "2021-08-12T12:00:56+0000" );
	script_cve_id( "CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 12:00:56 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-06-23 03:00:58 +0000 (Tue, 23 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for perl (openSUSE-SU-2020:0850-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0850-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00044.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'perl'
  package(s) announced via the openSUSE-SU-2020:0850-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for perl fixes the following issues:

  - CVE-2020-10543: Fixed a heap buffer overflow in regular expression
  compiler which could have allowed overwriting of allocated memory with
  attacker's data (bsc#1171863).

  - CVE-2020-10878: Fixed multiple integer overflows which could have
  allowed the insertion of instructions into the compiled form of Perl
  regular expression (bsc#1171864).

  - CVE-2020-12723: Fixed an attacker's corruption of the intermediate
  language state of a compiled regular expression (bsc#1171866).

  - Fixed a bad warning in features.ph (bsc#1172348).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-850=1" );
	script_tag( name: "affected", value: "'perl' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "perl", rpm: "perl~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-base", rpm: "perl-base~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-base-debuginfo", rpm: "perl-base-debuginfo~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-debuginfo", rpm: "perl-debuginfo~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-debugsource", rpm: "perl-debugsource~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-32bit", rpm: "perl-32bit~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-32bit-debuginfo", rpm: "perl-32bit-debuginfo~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-base-32bit", rpm: "perl-base-32bit~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-base-32bit-debuginfo", rpm: "perl-base-32bit-debuginfo~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "perl-doc", rpm: "perl-doc~5.26.1~lp151.9.6.1", rls: "openSUSELeap15.1" ) )){
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

