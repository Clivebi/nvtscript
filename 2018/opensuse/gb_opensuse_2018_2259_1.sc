if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851976" );
	script_version( "2021-06-29T02:00:29+0000" );
	script_cve_id( "CVE-2018-0360", "CVE-2018-0361" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-29 02:00:29 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 16:41:00 +0000 (Fri, 26 Apr 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:25:12 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for clamav (openSUSE-SU-2018:2259-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2259-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00027.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'clamav'
  package(s) announced via the openSUSE-SU-2018:2259-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for clamav to version 0.100.1 fixes the following issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-0360: HWP integer overflow, infinite loop vulnerability
  (bsc#1101410)

  - CVE-2018-0361: PDF object length check, unreasonably long time to parse
  relatively small file (bsc#1101412)

  - Buffer over-read in unRAR code due to missing max value checks in table
  initialization

  - Libmspack heap buffer over-read in CHM parser (bsc#1103040)

  - PDF parser bugs

  The following other changes were made:

  - Disable YARA support for licensing reasons (bsc#1101654).

  - Add HTTPS support for clamsubmit

  - Fix for DNS resolution for users on IPv4-only machines where IPv6 is not
  available or is link-local only

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-838=1" );
	script_tag( name: "affected", value: "clamav on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "clamav", rpm: "clamav~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debuginfo", rpm: "clamav-debuginfo~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-debugsource", rpm: "clamav-debugsource~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "clamav-devel", rpm: "clamav-devel~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libclamav7", rpm: "libclamav7~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libclamav7-debuginfo", rpm: "libclamav7-debuginfo~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libclammspack0", rpm: "libclammspack0~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libclammspack0-debuginfo", rpm: "libclammspack0-debuginfo~0.100.1~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

