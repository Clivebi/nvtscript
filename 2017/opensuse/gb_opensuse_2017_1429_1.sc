if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851560" );
	script_version( "2021-09-20T13:38:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-28 07:00:53 +0200 (Sun, 28 May 2017)" );
	script_cve_id( "CVE-2017-3289", "CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3512", "CVE-2017-3514", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for java-1_7_0-openjdk (openSUSE-SU-2017:1429-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for java-1_7_0-openjdk fixes
  the following issues: - Update to 2.6.10 - OpenJDK 7u141 (bsc#1034849) *
  Security fixes - S8163520, CVE-2017-3509: Reuse cache entries - S8163528,
  CVE-2017-3511: Better library loading - S8165626, CVE-2017-3512: Improved window
  framing - S8167110, CVE-2017-3514: Windows peering issue - S8169011,
  CVE-2017-3526: Resizing XML parse trees - S8170222, CVE-2017-3533: Better
  transfers of files - S8171121, CVE-2017-3539: Enhancing jar checking - S8171533,
  CVE-2017-3544: Better email transfer - S8172299: Improve class processing * New
  features - PR3347: jstack.stp should support AArch64 * Import of OpenJDK 7 u141
  build 0 - S4717864: setFont() does not update Fonts of Menus already on screen -
  S6474807: (smartcardio) CardTerminal.connect() throws CardException instead of
  CardNotPresentException - S6518907: cleanup IA64 specific code in Hotspot -
  S6869327: Add new C2 flag to keep safepoints in counted loops. - S7112912:
  Message 'Error occurred during initialization of VM' on boxes with lots of RAM -
  S7124213: [macosx] pack() does ignore size of a component doesn't on the other
  platforms - S7124219: [macosx] Unable to draw images to fullscreen - S7124552:
  [macosx] NullPointerException in getBufferStrategy() - S7148275: [macosx]
  setIconImages() not working correctly (distorted icon when minimized) -
  S7154841: [macosx] Popups appear behind taskbar - S7155957:
  closed/java/awt/MenuBar/MenuBarStress1/MenuBarStress1.java hangs on win 64 bit
  with jdk8 - S7160627: [macosx] TextArea has wrong initial size - S7167293:
  FtpURLConnection connection leak on FileNotFoundException - S7168851: [macosx]
  Netbeans crashes in CImage.nativeCreateNSImageFromArray - S7197203:
  sun/misc/URLClassPath/ClassnameCharTest.sh failed, compile error - S8005255:
  [macosx] Cleanup warnings in sun.lwawt - S8006088: Incompatible heap size flags
  accepted by VM - S8007295: Reduce number of warnings in awt classes - S8010722:
  assert: failed: heap size is too big for compressed oops - S8011059: [macosx]
  Support automatic @2x images loading on Mac OS X - S8014058: Regression tests
  for 8006088 - S8014489:
  tests/gc/arguments/Test(SerialCMSParallelG1)HeapSizeFlags jtreg tests invoke
  wrong class - S8016302: Change type of the number of GC workers to unsigned int
  (2) - S8024662: gc/arguments/TestUseCompressedOopsErgo.java does not compile. -
  S8024669: Native OOME when allocating after changes to maximum heap supporting
  Coops sizing on sparcv9 - S8024926: [macosx] AquaIcon HiDPI support ...
  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "java-1_7_0-openjdk on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:1429-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk", rpm: "java-1_7_0-openjdk~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-accessibility", rpm: "java-1_7_0-openjdk-accessibility~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap", rpm: "java-1_7_0-openjdk-bootstrap~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-debuginfo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-debugsource", rpm: "java-1_7_0-openjdk-bootstrap-debugsource~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-devel", rpm: "java-1_7_0-openjdk-bootstrap-devel~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-devel-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-devel-debuginfo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-headless", rpm: "java-1_7_0-openjdk-bootstrap-headless~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-headless-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-headless-debuginfo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debuginfo", rpm: "java-1_7_0-openjdk-debuginfo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debugsource", rpm: "java-1_7_0-openjdk-debugsource~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo", rpm: "java-1_7_0-openjdk-demo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo-debuginfo", rpm: "java-1_7_0-openjdk-demo-debuginfo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel", rpm: "java-1_7_0-openjdk-devel~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel-debuginfo", rpm: "java-1_7_0-openjdk-devel-debuginfo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless", rpm: "java-1_7_0-openjdk-headless~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless-debuginfo", rpm: "java-1_7_0-openjdk-headless-debuginfo~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-src", rpm: "java-1_7_0-openjdk-src~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-javadoc", rpm: "java-1_7_0-openjdk-javadoc~1.7.0.141~42.3.1", rls: "openSUSELeap42.2" ) )){
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
