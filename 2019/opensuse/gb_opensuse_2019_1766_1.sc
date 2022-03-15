if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852626" );
	script_version( "2021-09-07T14:01:38+0000" );
	script_cve_id( "CVE-2019-6237", "CVE-2019-8571", "CVE-2019-8583", "CVE-2019-8584", "CVE-2019-8586", "CVE-2019-8587", "CVE-2019-8594", "CVE-2019-8595", "CVE-2019-8596", "CVE-2019-8597", "CVE-2019-8601", "CVE-2019-8607", "CVE-2019-8608", "CVE-2019-8609", "CVE-2019-8610", "CVE-2019-8611", "CVE-2019-8615", "CVE-2019-8619", "CVE-2019-8622", "CVE-2019-8623" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 14:01:38 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-07-22 02:01:04 +0000 (Mon, 22 Jul 2019)" );
	script_name( "openSUSE: Security Advisory for webkit2gtk3 (openSUSE-SU-2019:1766-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.0" );
	script_xref( name: "openSUSE-SU", value: "2019:1766-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-07/msg00028.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2019:1766-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for webkit2gtk3 to version 2.24.2 fixes the following issues:

  Security issues fixed:

  - CVE-2019-6237, CVE-2019-8571, CVE-2019-8583, CVE-2019-8584,
  CVE-2019-8586, CVE-2019-8587, CVE-2019-8594, CVE-2019-8595,
  CVE-2019-8596, CVE-2019-8597, CVE-2019-8601, CVE-2019-8607,
  CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8615,
  CVE-2019-8611, CVE-2019-8619, CVE-2019-8622, CVE-2019-8623 (bsc#1135715).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1766=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1766=1" );
	script_tag( name: "affected", value: "'webkit2gtk3' package(s) on openSUSE Leap 15.0." );
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
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2WebExtension-4_0", rpm: "typelib-1_0-WebKit2WebExtension-4_0~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4", rpm: "webkit-jsc-4~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4-debuginfo", rpm: "webkit-jsc-4-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-devel", rpm: "webkit2gtk3-devel~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-minibrowser", rpm: "webkit2gtk3-minibrowser~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-minibrowser-debuginfo", rpm: "webkit2gtk3-minibrowser-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2", rpm: "webkit2gtk3-plugin-process-gtk2~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2-debuginfo", rpm: "webkit2gtk3-plugin-process-gtk2-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk3-lang", rpm: "libwebkit2gtk3-lang~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit", rpm: "libjavascriptcoregtk-4_0-18-32bit~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-32bit-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit", rpm: "libwebkit2gtk-4_0-37-32bit~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit-debuginfo", rpm: "libwebkit2gtk-4_0-37-32bit-debuginfo~2.24.2~lp150.2.22.1", rls: "openSUSELeap15.0" ) )){
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

