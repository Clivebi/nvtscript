if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852547" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2018-13785", "CVE-2019-7317" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-06-08 02:00:45 +0000 (Sat, 08 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for libpng16 (openSUSE-SU-2019:1530-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1530-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00021.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libpng16'
  package(s) announced via the openSUSE-SU-2019:1530-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libpng16 fixes the following issues:

  Security issues fixed:

  - CVE-2019-7317: Fixed a use-after-free vulnerability, triggered when
  png_image_free() was called under png_safe_execute (bsc#1124211).

  - CVE-2018-13785: Fixed a wrong calculation of row_factor in the
  png_check_chunk_length function in pngrutil.c, which could haved
  triggered and integer overflow and result in a divide-by-zero while
  processing a crafted PNG file, leading to a denial of service
  (bsc#1100687)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1530=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1530=1" );
	script_tag( name: "affected", value: "'libpng16' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16", rpm: "libpng16-16~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-debuginfo", rpm: "libpng16-16-debuginfo~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-compat-devel", rpm: "libpng16-compat-devel~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-debugsource", rpm: "libpng16-debugsource~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-devel", rpm: "libpng16-devel~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-tools", rpm: "libpng16-tools~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-tools-debuginfo", rpm: "libpng16-tools-debuginfo~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-32bit", rpm: "libpng16-16-32bit~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-16-32bit-debuginfo", rpm: "libpng16-16-32bit-debuginfo~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-compat-devel-32bit", rpm: "libpng16-compat-devel-32bit~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libpng16-devel-32bit", rpm: "libpng16-devel-32bit~1.6.34~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

