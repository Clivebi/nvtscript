if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852723" );
	script_version( "2021-09-07T11:01:32+0000" );
	script_cve_id( "CVE-2019-13616", "CVE-2019-13626" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 11:01:32 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-05 11:27:00 +0000 (Mon, 05 Apr 2021)" );
	script_tag( name: "creation_date", value: "2019-10-01 02:01:17 +0000 (Tue, 01 Oct 2019)" );
	script_name( "openSUSE: Security Advisory for SDL2 (openSUSE-SU-2019:2224-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:2224-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-09/msg00094.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'SDL2'
  package(s) announced via the openSUSE-SU-2019:2224-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for SDL2 fixes the following issues:

  Security issues fixed:

  - CVE-2019-13616: Fixed heap-based buffer over-read in BlitNtoN in
  video/SDL_blit_N.c (bsc#1141844).

  - CVE-2019-13626: Fixed integer overflow in IMA_ADPCM_decode() in
  audio/SDL_wave.c (bsc#1142031).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2224=1" );
	script_tag( name: "affected", value: "'SDL2' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "SDL2-debugsource", rpm: "SDL2-debugsource~2.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0", rpm: "libSDL2-2_0-0~2.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0-debuginfo", rpm: "libSDL2-2_0-0-debuginfo~2.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-devel", rpm: "libSDL2-devel~2.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0-32bit", rpm: "libSDL2-2_0-0-32bit~2.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-2_0-0-32bit-debuginfo", rpm: "libSDL2-2_0-0-32bit-debuginfo~2.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2-devel-32bit", rpm: "libSDL2-devel-32bit~2.0.8~lp150.2.9.1", rls: "openSUSELeap15.0" ) )){
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

