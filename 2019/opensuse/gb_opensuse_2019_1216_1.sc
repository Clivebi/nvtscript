if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852427" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2018-19490", "CVE-2018-19491", "CVE-2018-19492" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 20:15:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-04-17 02:01:07 +0000 (Wed, 17 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for gnuplot (openSUSE-SU-2019:1216-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1216-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00066.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnuplot'
  package(s) announced via the openSUSE-SU-2019:1216-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gnuplot fixes the following issues:

  Security issues fixed:

  - CVE-2018-19492: Fixed a buffer overflow in cairotrm_options function
  (bsc#1117463)

  - CVE-2018-19491: Fixed a buffer overflow in the PS_options function
  (bsc#1117464)

  - CVE-2018-19490: Fixed a heap-based buffer overflow in the
  df_generate_ascii_array_entry function (bsc#1117465)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1216=1" );
	script_tag( name: "affected", value: "'gnuplot' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "gnuplot", rpm: "gnuplot~5.2.2~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnuplot-debuginfo", rpm: "gnuplot-debuginfo~5.2.2~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnuplot-debugsource", rpm: "gnuplot-debugsource~5.2.2~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnuplot-doc", rpm: "gnuplot-doc~5.2.2~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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

