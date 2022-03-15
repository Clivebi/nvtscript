if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852854" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2019-15540" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 09:36:25 +0000 (Thu, 09 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for libmirage (openSUSE-SU-2019:2033-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2019:2033-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00086.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libmirage'
  package(s) announced via the openSUSE-SU-2019:2033-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libmirage fixes the following issues:

  CVE-2019-15540: The CSO filter in libMirage in CDemu did not validate the
  part size, triggering a heap-based buffer overflow that could lead to root
  access by a local user. [boo#1148087]

  - Update to new upstream release 3.2.2

  * ISO parser: fixed ISO9660/UDF pattern search for sector sizes 2332 and
  2336.

  * ISO parser: added support for Nintendo GameCube and Wii ISO images.

  * Extended medium type guess to distinguish between DVD and BluRay
  images based on length.

  * Removed fabrication of disc structures from the library (moved to
  CDEmu daemon).

  * MDS parser: cleanup of disc structure parsing, fixed the incorrectly
  set structure sizes.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2033=1" );
	script_tag( name: "affected", value: "'libmirage' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "libmirage-3_2", rpm: "libmirage-3_2~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage-3_2-debuginfo", rpm: "libmirage-3_2-debuginfo~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage-debuginfo", rpm: "libmirage-debuginfo~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage-debugsource", rpm: "libmirage-debugsource~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage-devel", rpm: "libmirage-devel~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage11", rpm: "libmirage11~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage11-debuginfo", rpm: "libmirage11-debuginfo~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-libmirage-3_2", rpm: "typelib-1_0-libmirage-3_2~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage-data", rpm: "libmirage-data~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmirage-lang", rpm: "libmirage-lang~3.2.2~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

