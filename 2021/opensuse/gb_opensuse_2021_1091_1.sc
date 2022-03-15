if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854034" );
	script_version( "2021-08-26T09:01:14+0000" );
	script_cve_id( "CVE-2021-29969", "CVE-2021-29970", "CVE-2021-29976", "CVE-2021-30547" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-12 17:28:00 +0000 (Thu, 12 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-05 03:02:20 +0000 (Thu, 05 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2021:1091-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:1091-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ABQT6TDIB2IQ4ZZNUZXMHLE7ZDVD4YBM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the openSUSE-SU-2021:1091-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaThunderbird fixes the following issues:

     Mozilla Thunderbird 78.12

  * fixed: Sending an email containing HTML links with spaces in the URL
         sometimes resulted in broken links

  * fixed: Folder Pane display theme fixes for macOS

  * fixed: Chat account settings did not always save as expected

  * fixed: RSS feed subscriptions sometimes lost

  * fixed: Calendar: A parsing error for alarm triggers of type 'DURATION'
         caused sync problems for some users

  * fixed: Various security fixes

     MFSA 2021-30 (bsc#1188275)

  * CVE-2021-29969: IMAP server responses sent by a MITM prior to STARTTLS
       could be processed

  * CVE-2021-29970: Use-after-free in accessibility features of a document

  * CVE-2021-30547: Out of bounds write in ANGLE

  * CVE-2021-29976: Memory safety bugs fixed in Thunderbird 78.12

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'MozillaThunderbird' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird", rpm: "MozillaThunderbird~78.12.0~lp152.2.48.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debuginfo", rpm: "MozillaThunderbird-debuginfo~78.12.0~lp152.2.48.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-debugsource", rpm: "MozillaThunderbird-debugsource~78.12.0~lp152.2.48.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-common", rpm: "MozillaThunderbird-translations-common~78.12.0~lp152.2.48.2", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaThunderbird-translations-other", rpm: "MozillaThunderbird-translations-other~78.12.0~lp152.2.48.2", rls: "openSUSELeap15.2" ) )){
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

