if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853204" );
	script_version( "2021-08-12T14:00:53+0000" );
	script_cve_id( "CVE-2020-12398", "CVE-2020-12405", "CVE-2020-12406", "CVE-2020-12410" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-22 16:15:00 +0000 (Wed, 22 Jul 2020)" );
	script_tag( name: "creation_date", value: "2020-06-13 03:00:40 +0000 (Sat, 13 Jun 2020)" );
	script_name( "openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2020:0799-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0799-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00019.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2020:0799-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaThunderbird fixes the following issues:

  Mozilla Thunderbird 68.9.0 (bsc#1172402)

  - CVE-2020-12405: Fixed a use-after-free in SharedWorkerService.

  - CVE-2020-12406: Fixed a JavaScript Type confusion with NativeTypes.

  - CVE-2020-12410: Fixed multiple memory safety issues

  - CVE-2020-12398: Fixed a potential information leak due to security
  downgrade with IMAP STARTTLS

  - Use a symbolic icon from branding internals

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-799=1" );
	script_tag( name: "affected", value: "'MozillaThunderbird' package(s) on openSUSE Leap 15.1." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~68.9.0~lp151.2.41.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~68.9.0~lp151.2.41.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~68.9.0~lp151.2.41.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~68.9.0~lp151.2.41.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~68.9.0~lp151.2.41.1", rls: "openSUSELeap15.1" ) )){
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
