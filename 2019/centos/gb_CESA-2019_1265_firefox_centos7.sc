if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883059" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_cve_id( "CVE-2018-18511", "CVE-2019-5798", "CVE-2019-7317", "CVE-2019-9797", "CVE-2019-9800", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11698" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-26 17:00:00 +0000 (Fri, 26 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-05-30 02:00:25 +0000 (Thu, 30 May 2019)" );
	script_name( "CentOS Update for firefox CESA-2019:1265 centos7 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:1265" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-May/023317.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2019:1265 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 60.7.0 ESR.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 67 and Firefox ESR 60.7
(CVE-2019-9800)

  * Mozilla: Cross-origin theft of images with createImageBitmap
(CVE-2019-9797)

  * Mozilla: Type confusion with object groups and UnboxedObjects
(CVE-2019-9816)

  * Mozilla: Stealing of cross-domain images using canvas (CVE-2019-9817)

  * Mozilla: Compartment mismatch with fetch API (CVE-2019-9819)

  * Mozilla: Use-after-free of ChromeEventHandler by DocShell (CVE-2019-9820)

  * Mozilla: Use-after-free in XMLHttpRequest (CVE-2019-11691)

  * Mozilla: Use-after-free removing listeners in the event listener manager
(CVE-2019-11692)

  * Mozilla: Buffer overflow in WebGL bufferdata on Linux (CVE-2019-11693)

  * mozilla: Cross-origin theft of images with ImageBitmapRenderingContext
(CVE-2018-18511)

  * chromium-browser: Out of bounds read in Skia (CVE-2019-5798)

  * Mozilla: Theft of user history data through drag and drop of hyperlinks
to and from bookmarks (CVE-2019-11698)

  * libpng: use-after-free in png_image_free in png.c (CVE-2019-7317)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'firefox' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "firefox", rpm: "firefox~60.7.0~1.el7.centos", rls: "CentOS7" ) )){
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

