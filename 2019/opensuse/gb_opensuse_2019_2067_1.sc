if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852689" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2019-1010319", "CVE-2019-11498" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-09 17:38:00 +0000 (Tue, 09 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-09-06 02:00:53 +0000 (Fri, 06 Sep 2019)" );
	script_name( "openSUSE: Security Advisory for wavpack (openSUSE-SU-2019:2067-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2067-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00015.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wavpack'
  package(s) announced via the openSUSE-SU-2019:2067-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wavpack fixes the following issues:

  Security issues fixed:

  - CVE-2019-1010319: Fixed use of uninitialized variable in
  ParseWave64HeaderConfig that can result in unexpected control flow,
  crashes, and segfaults (bsc#1141334).

  - CVE-2019-11498: Fixed possible denial of service (application crash) in
  WavpackSetConfiguration64 via a DFF file that lacks valid sample-rate
  data (bsc#1133384).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2067=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2067=1" );
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
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1", rpm: "libwavpack1~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1-debuginfo", rpm: "libwavpack1-debuginfo~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack", rpm: "wavpack~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack-debuginfo", rpm: "wavpack-debuginfo~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack-debugsource", rpm: "wavpack-debugsource~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wavpack-devel", rpm: "wavpack-devel~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1-32bit", rpm: "libwavpack1-32bit~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwavpack1-32bit-debuginfo", rpm: "libwavpack1-32bit-debuginfo~5.1.0~lp150.3.6.1", rls: "openSUSELeap15.0" ) )){
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

