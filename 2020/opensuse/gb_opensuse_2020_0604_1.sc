if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853142" );
	script_version( "2021-08-13T03:00:58+0000" );
	script_cve_id( "CVE-2020-0561", "CVE-2020-6458", "CVE-2020-6459", "CVE-2020-6460", "CVE-2020-6462" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-13 03:00:58 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-02 16:15:00 +0000 (Thu, 02 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-05-04 03:00:41 +0000 (Mon, 04 May 2020)" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2020:0604-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0604-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-05/msg00009.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:0604-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for chromium fixes the following issues:

  Chromium was updated to 81.0.4044.129 (boo#1170107):

  - CVE-2020-0561: Fixed a use after free in storage

  - CVE-2020-6462: Fixed a use after free in task scheduling

  - CVE-2020-6459: Fixed a use after free in payments

  - CVE-2020-6460: Fixed an insufficient data validation in URL formatting

  - CVE-2020-6458: Fixed an out of bounds read and write in PDFium


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-604=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-604=1" );
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
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~81.0.4044.129~lp151.2.85.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~81.0.4044.129~lp151.2.85.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~81.0.4044.129~lp151.2.85.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~81.0.4044.129~lp151.2.85.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~81.0.4044.129~lp151.2.85.1", rls: "openSUSELeap15.1" ) )){
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
