if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.854031" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2021-21775", "CVE-2021-21779", "CVE-2021-30663", "CVE-2021-30665", "CVE-2021-30689", "CVE-2021-30720", "CVE-2021-30734", "CVE-2021-30744", "CVE-2021-30749", "CVE-2021-30758", "CVE-2021-30795", "CVE-2021-30797", "CVE-2021-30799" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-16 14:10:00 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-04 03:01:39 +0000 (Wed, 04 Aug 2021)" );
	script_name( "openSUSE: Security Advisory for webkit2gtk3 (openSUSE-SU-2021:2598-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.3" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:2598-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/554N5QKF5U43OFZQKL2FBBMYD5YD3BX7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2021:2598-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for webkit2gtk3 fixes the following issues:

  - Update to version 2.32.3:

  - CVE-2021-21775: Fixed a use-after-free vulnerability in the way certain
       events are processed for ImageLoader objects. A specially crafted web
       page can lead to a potential information leak and further memory
       corruption. A victim must be tricked into visiting a malicious web page
       to trigger this vulnerability. (bsc#1188697)

  - CVE-2021-21779: Fixed a use-after-free vulnerability in the way that
       WebKit GraphicsContext handles certain events. A specially crafted web
       page can lead to a potential information leak and further memory
       corruption. A victim must be tricked into visiting a malicious web page
       to trigger this vulnerability. (bsc#1188697)

  - CVE-2021-30663: An integer overflow was addressed with improved input
       validation. (bsc#1188697)

  - CVE-2021-30665: A memory corruption issue was addressed with improved
       state management. (bsc#1188697)

  - CVE-2021-30689: A logic issue was addressed with improved state
       management. (bsc#1188697)

  - CVE-2021-30720: A logic issue was addressed with improved restrictions.
       (bsc#1188697)

  - CVE-2021-30734: Multiple memory corruption issues were addressed with
       improved memory handling. (bsc#1188697)

  - CVE-2021-30744: A cross-origin issue with iframe elements was addressed
       with improved tracking of security origins. (bsc#1188697)

  - CVE-2021-30749: Multiple memory corruption issues were addressed with
       improved memory handling. (bsc#1188697)

  - CVE-2021-30758: A type confusion issue was addressed with improved state
       handling. (bsc#1188697)

  - CVE-2021-30795: A use after free issue was addressed with improved
       memory management. (bsc#1188697)

  - CVE-2021-30797: This issue was addressed with improved checks.
       (bsc#1188697)

  - CVE-2021-30799: Multiple memory corruption issues were addressed with
       improved memory handling. (bsc#1188697)" );
	script_tag( name: "affected", value: "'webkit2gtk3' package(s) on openSUSE Leap 15.3." );
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
if(release == "openSUSELeap15.3"){
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2WebExtension-4_0", rpm: "typelib-1_0-WebKit2WebExtension-4_0~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4", rpm: "webkit-jsc-4~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4-debuginfo", rpm: "webkit-jsc-4-debuginfo~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-devel", rpm: "webkit2gtk3-devel~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-minibrowser", rpm: "webkit2gtk3-minibrowser~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-minibrowser-debuginfo", rpm: "webkit2gtk3-minibrowser-debuginfo~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk3-lang", rpm: "libwebkit2gtk3-lang~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit", rpm: "libjavascriptcoregtk-4_0-18-32bit~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-32bit-debuginfo~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit", rpm: "libwebkit2gtk-4_0-37-32bit~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit-debuginfo", rpm: "libwebkit2gtk-4_0-37-32bit-debuginfo~2.32.3~9.1", rls: "openSUSELeap15.3" ) )){
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

