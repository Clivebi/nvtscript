if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851645" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-11 07:31:25 +0100 (Sat, 11 Nov 2017)" );
	script_cve_id( "CVE-2016-7586", "CVE-2016-7589", "CVE-2016-7592", "CVE-2016-7599", "CVE-2016-7623", "CVE-2016-7632", "CVE-2016-7635", "CVE-2016-7639", "CVE-2016-7641", "CVE-2016-7645", "CVE-2016-7652", "CVE-2016-7654", "CVE-2016-7656", "CVE-2017-2350", "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356", "CVE-2017-2362", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365", "CVE-2017-2366", "CVE-2017-2369", "CVE-2017-2371", "CVE-2017-2373", "CVE-2017-2496", "CVE-2017-2510", "CVE-2017-2538", "CVE-2017-2539", "CVE-2017-7018", "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037", "CVE-2017-7039", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7061", "CVE-2017-7064" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for webkit2gtk3 (openSUSE-SU-2017:2991-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for webkit2gtk3 to version 2.18.0 fixes the following issues:

  These security issues were fixed:

  - CVE-2017-7039: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7018: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7030: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7037: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7034: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7055: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7056: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7064: An issue was fixed that allowed remote attackers to
  bypass intended memory-read restrictions via a crafted app (bsc#1050469).

  - CVE-2017-7061: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7048: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-7046: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1050469).

  - CVE-2017-2538: An issue was fixed that allowed remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption
  and application crash) via a crafted web site (bsc#1045460)

  - CVE-2017-2496: An issue was fixed that allowed remote attackers to
 ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "webkit2gtk3 on openSUSE Leap 42.3, openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:2991-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSELeap42\\.2|openSUSELeap42\\.3)" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2WebExtension-4_0", rpm: "typelib-1_0-WebKit2WebExtension-4_0~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4", rpm: "webkit-jsc-4~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4-debuginfo", rpm: "webkit-jsc-4-debuginfo~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-devel", rpm: "webkit2gtk3-devel~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2", rpm: "webkit2gtk3-plugin-process-gtk2~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2-debuginfo", rpm: "webkit2gtk3-plugin-process-gtk2-debuginfo~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit", rpm: "libjavascriptcoregtk-4_0-18-32bit~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo-32bit", rpm: "libjavascriptcoregtk-4_0-18-debuginfo-32bit~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit", rpm: "libwebkit2gtk-4_0-37-32bit~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo-32bit", rpm: "libwebkit2gtk-4_0-37-debuginfo-32bit~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk3-lang", rpm: "libwebkit2gtk3-lang~2.18.0~2.3.1", rls: "openSUSELeap42.2" ) )){
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2WebExtension-4_0", rpm: "typelib-1_0-WebKit2WebExtension-4_0~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4", rpm: "webkit-jsc-4~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit-jsc-4-debuginfo", rpm: "webkit-jsc-4-debuginfo~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-devel", rpm: "webkit2gtk3-devel~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2", rpm: "webkit2gtk3-plugin-process-gtk2~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-plugin-process-gtk2-debuginfo", rpm: "webkit2gtk3-plugin-process-gtk2-debuginfo~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-32bit", rpm: "libjavascriptcoregtk-4_0-18-32bit~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo-32bit", rpm: "libjavascriptcoregtk-4_0-18-debuginfo-32bit~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-32bit", rpm: "libwebkit2gtk-4_0-37-32bit~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo-32bit", rpm: "libwebkit2gtk-4_0-37-debuginfo-32bit~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk3-lang", rpm: "libwebkit2gtk3-lang~2.18.0~5.1", rls: "openSUSELeap42.3" ) )){
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

