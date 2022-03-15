if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852496" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2019-11070", "CVE-2019-6201", "CVE-2019-6251", "CVE-2019-7285", "CVE-2019-7292", "CVE-2019-8503", "CVE-2019-8506", "CVE-2019-8515", "CVE-2019-8524", "CVE-2019-8535", "CVE-2019-8536", "CVE-2019-8544", "CVE-2019-8551", "CVE-2019-8558", "CVE-2019-8559", "CVE-2019-8563" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-14 02:00:57 +0000 (Tue, 14 May 2019)" );
	script_name( "openSUSE: Security Advisory for webkit2gtk3 (openSUSE-SU-2019:1391-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1391-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00031.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2019:1391-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for webkit2gtk3 to version 2.24.1 fixes the following issues:

  Security issues fixed:

  - CVE-2019-6201, CVE-2019-6251, CVE-2019-7285, CVE-2019-7292,
  CVE-2019-8503, CVE-2019-8506, CVE-2019-8515, CVE-2019-8524,
  CVE-2019-8535, CVE-2019-8536, CVE-2019-8544, CVE-2019-8551,
  CVE-2019-8558, CVE-2019-8559, CVE-2019-8563, CVE-2019-11070
  (bsc#1132256).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1391=1" );
	script_tag( name: "affected", value: "'webkit2gtk3' package(s) on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2WebExtension-4_0", rpm: "typelib-1_0-WebKit2WebExtension-4_0~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4", rpm: "webkit-jsc-4~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4-debuginfo", rpm: "webkit-jsc-4-debuginfo~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-devel", rpm: "webkit2gtk3-devel~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-minibrowser", rpm: "webkit2gtk3-minibrowser~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-minibrowser-debuginfo", rpm: "webkit2gtk3-minibrowser-debuginfo~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2", rpm: "webkit2gtk3-plugin-process-gtk2~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2-debuginfo", rpm: "webkit2gtk3-plugin-process-gtk2-debuginfo~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk3-lang", rpm: "libwebkit2gtk3-lang~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit", rpm: "libjavascriptcoregtk-4_0-18-32bit~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo-32bit", rpm: "libjavascriptcoregtk-4_0-18-debuginfo-32bit~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit", rpm: "libwebkit2gtk-4_0-37-32bit~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo-32bit", rpm: "libwebkit2gtk-4_0-37-debuginfo-32bit~2.24.1~27.1", rls: "openSUSELeap42.3" ) )){
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

