if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850555" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2013-12-03 14:46:38 +0530 (Tue, 03 Dec 2013)" );
	script_cve_id( "CVE-2013-2931", "CVE-2013-6621", "CVE-2013-6622", "CVE-2013-6623", "CVE-2013-6624", "CVE-2013-6625", "CVE-2013-6626", "CVE-2013-6627", "CVE-2013-6628", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6631", "CVE-2013-6632" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "openSUSE: Security Advisory for chromium (openSUSE-SU-2013:1777-1)" );
	script_tag( name: "affected", value: "chromium on openSUSE 12.2" );
	script_tag( name: "insight", value: "Chromium was updated to 31.0.1650.57: Stable channel update:

  - Security Fixes:

  * CVE-2013-6632: Multiple memory corruption issues.

  - Update to Chromium 31.0.1650.48 (bnc#850430) Stable
  Channel update:

  - Security fixes:

  * CVE-2013-6621: Use after free related to speech input
  elements..

  * CVE-2013-6622: Use after free related to media
  elements.

  * CVE-2013-6623: Out of bounds read in SVG.

  * CVE-2013-6624: Use after free related to id
  attribute strings.

  * CVE-2013-6625: Use after free in DOM ranges.

  * CVE-2013-6626: Address bar spoofing related to
  interstitial warnings.

  * CVE-2013-6627: Out of bounds read in HTTP parsing.

  * CVE-2013-6628: Issue with certificates not being
  checked during TLS renegotiation.

  * CVE-2013-2931: Various fixes from internal audits,
  fuzzing and other initiatives.

  * CVE-2013-6629: Read of uninitialized memory in
  libjpeg and libjpeg-turbo.

  * CVE-2013-6630: Read of uninitialized memory in
  libjpeg-turbo.

  * CVE-2013-6631: Use after free in libjingle.

  - Added patch chromium-fix-chromedriver-build.diff to fix
  the  chromedriver build" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "openSUSE-SU", value: "2013:1777-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE12\\.2" );
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
if(release == "openSUSE12.2"){
	if(!isnull( res = isrpmvuln( pkg: "chromedriver", rpm: "chromedriver~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromedriver-debuginfo", rpm: "chromedriver-debuginfo~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debuginfo", rpm: "chromium-debuginfo~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-debugsource", rpm: "chromium-debugsource~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-gnome", rpm: "chromium-desktop-gnome~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-desktop-kde", rpm: "chromium-desktop-kde~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo", rpm: "chromium-ffmpegsumo~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-ffmpegsumo-debuginfo", rpm: "chromium-ffmpegsumo-debuginfo~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-suid-helper", rpm: "chromium-suid-helper~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "chromium-suid-helper-debuginfo", rpm: "chromium-suid-helper-debuginfo~31.0.1650.57~1.54.1", rls: "openSUSE12.2" ) )){
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

