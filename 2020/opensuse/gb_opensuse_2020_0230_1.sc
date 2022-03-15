if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853040" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-6796", "CVE-2020-6797", "CVE-2020-6798", "CVE-2020-6799", "CVE-2020-6800" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-12 00:15:00 +0000 (Thu, 12 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-02-19 04:02:05 +0000 (Wed, 19 Feb 2020)" );
	script_name( "openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2020:0230-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0230-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-02/msg00024.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the openSUSE-SU-2020:0230-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaFirefox fixes the following issues:

  - Firefox Extended Support Release 68.5.0 ESR

  * Fixed: Various stability and security fixes

  - Mozilla Firefox ESR68.5 MFSA 2020-06 (bsc#1163368)

  * CVE-2020-6796 (bmo#1610426) Missing bounds check on shared memory read
  in the parent process

  * CVE-2020-6797 (bmo#1596668) Extensions granted downloads.open
  permission could open arbitrary applications on Mac OSX

  * CVE-2020-6798 (bmo#1602944) Incorrect parsing of template tag could
  result in JavaScript injection

  * CVE-2020-6799 (bmo#1606596) Arbitrary code execution when opening pdf
  links from other applications, when Firefox is configured as default
  pdf reader

  * CVE-2020-6800 (bmo#1595786, bmo#1596706, bmo#1598543, bmo#1604851,
  bmo#1605777, bmo#1608580, bmo#1608785) Memory safety bugs fixed in
  Firefox 73 and Firefox ESR 68.5

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-230=1" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-upstream", rpm: "MozillaFirefox-branding-upstream~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-buildsymbols", rpm: "MozillaFirefox-buildsymbols~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~68.5.0~lp151.2.30.1", rls: "openSUSELeap15.1" ) )){
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

