if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853590" );
	script_version( "2021-08-26T13:01:12+0000" );
	script_cve_id( "CVE-2021-23968", "CVE-2021-23969", "CVE-2021-23973", "CVE-2021-23978" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 13:01:12 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:56:03 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for MozillaFirefox (openSUSE-SU-2021:0373-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0373-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3JU7JWCNX3KH2TP7LILEHP3VXYK7BTLC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the openSUSE-SU-2021:0373-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaFirefox fixes the following issues:

  - Firefox Extended Support Release 78.8.0 ESR

  * Fixed: Various stability, functionality, and security fixes MFSA
         2021-08 (bsc#1182614)

  * CVE-2021-23969: Content Security Policy violation report could have
         contained the destination of a redirect

  * CVE-2021-23968: Content Security Policy violation report could have
         contained the destination of a redirect

  * CVE-2021-23973: MediaError message property could have leaked
         information about cross-origin resources

  * CVE-2021-23978: Memory safety bugs fixed in Firefox 86 and Firefox ESR
         78.8

     This update was imported from the SUSE:SLE-15-SP2:Update update project." );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-branding-upstream", rpm: "MozillaFirefox-branding-upstream~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-buildsymbols", rpm: "MozillaFirefox-buildsymbols~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-common", rpm: "MozillaFirefox-translations-common~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations-other", rpm: "MozillaFirefox-translations-other~78.8.0~lp152.2.49.1", rls: "openSUSELeap15.2" ) )){
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

