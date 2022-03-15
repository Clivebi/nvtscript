if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853483" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-15095", "CVE-2020-8201", "CVE-2020-8252" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-11 11:15:00 +0000 (Mon, 11 Jan 2021)" );
	script_tag( name: "creation_date", value: "2020-10-06 03:03:00 +0000 (Tue, 06 Oct 2020)" );
	script_name( "openSUSE: Security Advisory for nodejs12 (openSUSE-SU-2020:1616-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1616-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00011.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nodejs12'
  package(s) announced via the openSUSE-SU-2020:1616-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for nodejs12 fixes the following issues:

  - nodejs12 was updated to 12.18.4 LTS:

  - CVE-2020-8201: Fixed an HTTP Request Smuggling due to CR-to-Hyphen
  conversion (bsc#1176605).

  - CVE-2020-8252: Fixed a buffer overflow in realpath (bsc#1176589).

  - CVE-2020-15095: Fixed an information leak through log files
  (bsc#1173937).

  - Explicitly add -fno-strict-aliasing to CFLAGS to fix compilation
  on Aarch64 with gcc10 (bsc#1172686)

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1616=1" );
	script_tag( name: "affected", value: "'nodejs12' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "nodejs12", rpm: "nodejs12~12.18.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debuginfo", rpm: "nodejs12-debuginfo~12.18.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-debugsource", rpm: "nodejs12-debugsource~12.18.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-devel", rpm: "nodejs12-devel~12.18.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "npm12", rpm: "npm12~12.18.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nodejs12-docs", rpm: "nodejs12-docs~12.18.4~lp152.3.6.1", rls: "openSUSELeap15.2" ) )){
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

