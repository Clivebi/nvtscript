if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853487" );
	script_version( "2021-08-16T06:00:52+0000" );
	script_cve_id( "CVE-2020-15095" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-16 06:00:52 +0000 (Mon, 16 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-11 11:15:00 +0000 (Mon, 11 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-10-11 03:00:52 +0000 (Sun, 11 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for nodejs8 (openSUSE-SU-2020:1644-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:1644-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00015.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs8'
  package(s) announced via the openSUSE-SU-2020:1644-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs8 fixes the following issues:

  - CVE-2020-15095: Fixed information leak through log files (bsc#1173937).

  - Explicitly add -fno-strict-aliasing to CFLAGS to fix compilation
  on Aarch64 with gcc10 (bsc#1172686).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1644=1" );
	script_tag( name: "affected", value: "'nodejs8' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "nodejs8", rpm: "nodejs8~8.17.0~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-debuginfo", rpm: "nodejs8-debuginfo~8.17.0~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-debugsource", rpm: "nodejs8-debugsource~8.17.0~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-devel", rpm: "nodejs8-devel~8.17.0~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm8", rpm: "npm8~8.17.0~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs8-docs", rpm: "nodejs8-docs~8.17.0~lp151.2.21.1", rls: "openSUSELeap15.1" ) )){
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

