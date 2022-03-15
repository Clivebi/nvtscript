if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851975" );
	script_version( "2021-06-28T11:00:33+0000" );
	script_cve_id( "CVE-2018-11646", "CVE-2018-4190", "CVE-2018-4199", "CVE-2018-4218", "CVE-2018-4222", "CVE-2018-4232", "CVE-2018-4233" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-28 11:00:33 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-07 21:09:00 +0000 (Thu, 07 Mar 2019)" );
	script_tag( name: "creation_date", value: "2018-10-26 06:24:51 +0200 (Fri, 26 Oct 2018)" );
	script_name( "openSUSE: Security Advisory for webkit2gtk3 (openSUSE-SU-2018:2285-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2018:2285-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00031.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2018:2285-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for webkit2gtk3 to version 2.20.3 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-4190: An unspecified issue allowed remote attackers to obtain
  sensitive credential information that is transmitted during a CSS
  mask-image fetch (bsc#1097693).

  - CVE-2018-4199: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (buffer overflow and
  application crash) via a crafted web site (bsc#1097693)

  - CVE-2018-4218: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site that triggers an
  @generatorState use-after-free (bsc#1097693)

  - CVE-2018-4222: An unspecified issue allowed remote attackers to execute
  arbitrary code via a crafted web site that leverages a
  getWasmBufferFromValue
  out-of-bounds read during WebAssembly compilation (bsc#1097693)

  - CVE-2018-4232: An unspecified issue allowed remote attackers to
  overwrite cookies via a crafted web site (bsc#1097693)

  - CVE-2018-4233: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1097693)

  - CVE-2018-11646: webkitFaviconDatabaseSetIconForPageURL and
  webkitFaviconDatabaseSetIconURLForPageURL mishandle an unset pageURL,
  leading to an application crash (bsc#1095611).

  These non-security issues were fixed:

  - Disable Gigacage if mmap fails to allocate in Linux.

  - Add user agent quirk for paypal website.

  - Fix a network process crash when trying to get cookies of about:blank
  page.

  - Fix UI process crash when closing the window under Wayland.

  - Fix several crashes and rendering issues.

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-845=1" );
	script_tag( name: "affected", value: "webkit2gtk3 on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2WebExtension-4_0", rpm: "typelib-1_0-WebKit2WebExtension-4_0~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4", rpm: "webkit-jsc-4~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4-debuginfo", rpm: "webkit-jsc-4-debuginfo~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-devel", rpm: "webkit2gtk3-devel~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2", rpm: "webkit2gtk3-plugin-process-gtk2~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2-debuginfo", rpm: "webkit2gtk3-plugin-process-gtk2-debuginfo~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit", rpm: "libjavascriptcoregtk-4_0-18-32bit~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-32bit-debuginfo~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit", rpm: "libwebkit2gtk-4_0-37-32bit~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit-debuginfo", rpm: "libwebkit2gtk-4_0-37-32bit-debuginfo~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk3-lang", rpm: "libwebkit2gtk3-lang~2.20.3~lp150.2.3.1", rls: "openSUSELeap15.0" ) )){
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

