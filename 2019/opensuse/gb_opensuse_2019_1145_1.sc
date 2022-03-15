if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852396" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2018-19840", "CVE-2018-19841" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-15 13:15:00 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-04-05 02:00:48 +0000 (Fri, 05 Apr 2019)" );
	script_name( "openSUSE: Security Advisory for wavpack (openSUSE-SU-2019:1145-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1145-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00029.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wavpack'
  package(s) announced via the openSUSE-SU-2019:1145-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wavpack fixes the following issues:

  Security issues fixed:

  - CVE-2018-19840: Fixed a denial-of-service in the WavpackPackInit
  function from pack_utils.c (bsc#1120930)

  - CVE-2018-19841: Fixed a denial-of-service in the
  WavpackVerifySingleBlock function from open_utils.c (bsc#1120929)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1145=1" );
	script_tag( name: "affected", value: "'wavpack' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1", rpm: "libwavpack1~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1-debuginfo", rpm: "libwavpack1-debuginfo~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack", rpm: "wavpack~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack-debuginfo", rpm: "wavpack-debuginfo~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack-debugsource", rpm: "wavpack-debugsource~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack-devel", rpm: "wavpack-devel~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1-32bit", rpm: "libwavpack1-32bit~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1-32bit-debuginfo", rpm: "libwavpack1-32bit-debuginfo~5.1.0~lp150.3.3.1", rls: "openSUSELeap15.0" ) )){
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

