if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853238" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-6509" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-18 18:15:00 +0000 (Fri, 18 Sep 2020)" );
	script_tag( name: "creation_date", value: "2020-06-29 03:01:00 +0000 (Mon, 29 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2020:0887-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0887-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00059.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:0887-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

  Update to 83.0.4103.116 boo#1173251:

  * CVE-2020-6509: Use after free in extensions

  - Add patch to work with new ffmpeg (bsc#1173292)

  - Add multimedia fix for disabled location and also try one additional
  patch from Debian on the same issue boo#1173107

  - Disable wayland integration on openSUSE Leap 15.x (boo#1173187
  boo#1173188 boo#1173254)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-887=1" );
	script_tag( name: "affected", value: "'chromium' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~83.0.4103.116~lp151.2.106.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~83.0.4103.116~lp151.2.106.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~83.0.4103.116~lp151.2.106.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~83.0.4103.116~lp151.2.106.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~83.0.4103.116~lp151.2.106.1", rls: "openSUSELeap15.1" ) )){
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

