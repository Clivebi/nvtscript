if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852135" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-3839", "CVE-2018-3977" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-28 15:42:00 +0000 (Tue, 28 Jul 2020)" );
	script_tag( name: "creation_date", value: "2018-11-21 06:03:41 +0100 (Wed, 21 Nov 2018)" );
	script_name( "openSUSE: Security Advisory for SDL2_image (openSUSE-SU-2018:3828-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2018:3828-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00034.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'SDL2_image'
  package(s) announced via the openSUSE-SU-2018:3828-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for SDL2_image fixes the following issues:

  Security issues fixed:

  - CVE-2018-3839: Fixed an exploitable code execution vulnerability that
  existed in the XCF image rendering functionality of the Simple
  DirectMedia Layer (bsc#1089087).

  - CVE-2018-3977: Fixed a possible code execution via creafted XCF image
  that could have caused a heap overflow (bsc#1114519).

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1433=1" );
	script_tag( name: "affected", value: "SDL2_image on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "SDL2_image-debugsource", rpm: "SDL2_image-debugsource~2.0.4~13.13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2_image-2_0-0", rpm: "libSDL2_image-2_0-0~2.0.4~13.13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2_image-2_0-0-debuginfo", rpm: "libSDL2_image-2_0-0-debuginfo~2.0.4~13.13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2_image-devel", rpm: "libSDL2_image-devel~2.0.4~13.13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2_image-2_0-0-32bit", rpm: "libSDL2_image-2_0-0-32bit~2.0.4~13.13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2_image-2_0-0-debuginfo-32bit", rpm: "libSDL2_image-2_0-0-debuginfo-32bit~2.0.4~13.13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libSDL2_image-devel-32bit", rpm: "libSDL2_image-devel-32bit~2.0.4~13.13.1", rls: "openSUSELeap42.3" ) )){
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

