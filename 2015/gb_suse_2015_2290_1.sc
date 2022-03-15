if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851143" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-12-18 05:45:07 +0100 (Fri, 18 Dec 2015)" );
	script_cve_id( "CVE-2015-6764", "CVE-2015-6765", "CVE-2015-6766", "CVE-2015-6767", "CVE-2015-6768", "CVE-2015-6769", "CVE-2015-6770", "CVE-2015-6771", "CVE-2015-6772", "CVE-2015-6773", "CVE-2015-6774", "CVE-2015-6775", "CVE-2015-6776", "CVE-2015-6777", "CVE-2015-6778", "CVE-2015-6779", "CVE-2015-6780", "CVE-2015-6781", "CVE-2015-6782", "CVE-2015-6783", "CVE-2015-6784", "CVE-2015-6785", "CVE-2015-6786", "CVE-2015-6787", "CVE-2015-6788", "CVE-2015-6789", "CVE-2015-6790", "CVE-2015-6791" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for Chromium (openSUSE-SU-2015:2290-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Chromium'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Chromium was updated to 47.0.2526.80 to fix security issues and bugs.

  The following vulnerabilities were fixed:

  * CVE-2015-6788: Type confusion in extensions

  * CVE-2015-6789: Use-after-free in Blink

  * CVE-2015-6790: Escaping issue in saved pages

  * CVE-2015-6791: Various fixes from internal audits, fuzzing and other
  initiatives

  The following vulnerabilities were fixed in 47.0.2526.73:

  * CVE-2015-6765: Use-after-free in AppCache

  * CVE-2015-6766: Use-after-free in AppCache

  * CVE-2015-6767: Use-after-free in AppCache

  * CVE-2015-6768: Cross-origin bypass in DOM

  * CVE-2015-6769: Cross-origin bypass in core

  * CVE-2015-6770: Cross-origin bypass in DOM

  * CVE-2015-6771: Out of bounds access in v8

  * CVE-2015-6772: Cross-origin bypass in DOM

  * CVE-2015-6764: Out of bounds access in v8

  * CVE-2015-6773: Out of bounds access in Skia

  * CVE-2015-6774: Use-after-free in Extensions

  * CVE-2015-6775: Type confusion in PDFium

  * CVE-2015-6776: Out of bounds access in PDFium

  * CVE-2015-6777: Use-after-free in DOM

  * CVE-2015-6778: Out of bounds access in PDFium

  * CVE-2015-6779: Scheme bypass in PDFium

  * CVE-2015-6780: Use-after-free in Infobars

  * CVE-2015-6781: Integer overflow in Sfntly

  * CVE-2015-6782: Content spoofing in Omnibox

  * CVE-2015-6783: Signature validation issue in Android Crazy Linker.

  * CVE-2015-6784: Escaping issue in saved pages

  * CVE-2015-6785: Wildcard matching issue in CSP

  * CVE-2015-6786: Scheme bypass in CSP

  * CVE-2015-6787: Various fixes from internal audits, fuzzing  and other
  initiatives.

  * Multiple vulnerabilities in V8 fixed at the tip of the 4.7 branch
  (currently 4.7.80.23)" );
	script_tag( name: "affected", value: "Chromium on openSUSE 13.2, openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:2290-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(openSUSE13\\.2|openSUSE13\\.1)" );
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
if(release == "openSUSE13.2"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-gnome", rpm: "chromium-desktop-gnome~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-kde", rpm: "chromium-desktop-kde~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo", rpm: "chromium-ffmpegsumo~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo-debuginfo", rpm: "chromium-ffmpegsumo-debuginfo~47.0.2526.80~61.1", rls: "openSUSE13.2" ) )){
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
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-gnome", rpm: "chromium-desktop-gnome~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-kde", rpm: "chromium-desktop-kde~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo", rpm: "chromium-ffmpegsumo~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo-debuginfo", rpm: "chromium-ffmpegsumo-debuginfo~47.0.2526.80~116.1", rls: "openSUSE13.1" ) )){
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

