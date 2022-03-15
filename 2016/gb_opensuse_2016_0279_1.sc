if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851180" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-02-02 17:15:35 +0100 (Tue, 02 Feb 2016)" );
	script_cve_id( "CVE-2015-4871", "CVE-2015-7575", "CVE-2015-8126", "CVE-2015-8472", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for java-1_7_0-openjdk (openSUSE-SU-2016:0279-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "java-1_7_0-openjdk was updated to version 7u95 to fix 9 security issues.
  (bsc#962743)

  - CVE-2015-4871: Rebinding of the receiver of a DirectMethodHandle may
  allow a protected method to be accessed

  - CVE-2015-7575: Further reduce use of MD5 (SLOTH) (bsc#960996)

  - CVE-2015-8126: Vulnerability in the AWT component related to
  splashscreen displays

  - CVE-2015-8472: Vulnerability in the AWT component, addressed by same fix

  - CVE-2016-0402: Vulnerability in the Networking component related to URL
  processing

  - CVE-2016-0448: Vulnerability in the JMX component related to attribute
  processing

  - CVE-2016-0466: Vulnerability in the JAXP component, related to limits

  - CVE-2016-0483: Vulnerability in the AWT component related to image
  decoding

  - CVE-2016-0494: Vulnerability in 2D component related to font actions

  The following bugs were fixed:

  - bsc#939523: java-1_7_0-openjdk-headless had X dependencies, move
  libjavagtk to full package

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "java-1_7_0-openjdk on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0279-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk", rpm: "java-1_7_0-openjdk~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-accessibility", rpm: "java-1_7_0-openjdk-accessibility~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debuginfo", rpm: "java-1_7_0-openjdk-debuginfo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debugsource", rpm: "java-1_7_0-openjdk-debugsource~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo", rpm: "java-1_7_0-openjdk-demo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo-debuginfo", rpm: "java-1_7_0-openjdk-demo-debuginfo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel", rpm: "java-1_7_0-openjdk-devel~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel-debuginfo", rpm: "java-1_7_0-openjdk-devel-debuginfo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless", rpm: "java-1_7_0-openjdk-headless~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless-debuginfo", rpm: "java-1_7_0-openjdk-headless-debuginfo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-src", rpm: "java-1_7_0-openjdk-src~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap", rpm: "java-1_7_0-openjdk-bootstrap~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-debuginfo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-debugsource", rpm: "java-1_7_0-openjdk-bootstrap-debugsource~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-devel", rpm: "java-1_7_0-openjdk-bootstrap-devel~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-devel-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-devel-debuginfo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-headless", rpm: "java-1_7_0-openjdk-bootstrap-headless~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-headless-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-headless-debuginfo~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-javadoc", rpm: "java-1_7_0-openjdk-javadoc~1.7.0.95~25.1", rls: "openSUSELeap42.1" ) )){
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

