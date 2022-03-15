if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850671" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-09-18 10:27:41 +0200 (Fri, 18 Sep 2015)" );
	script_cve_id( "CVE-2014-3566", "CVE-2014-6585", "CVE-2014-6587", "CVE-2014-6591", "CVE-2014-6593", "CVE-2014-6601", "CVE-2015-0383", "CVE-2015-0395", "CVE-2015-0400", "CVE-2015-0407", "CVE-2015-0408", "CVE-2015-0410", "CVE-2015-0412" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for java-1_7_0-openjdk (openSUSE-SU-2015:0190-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenJDK was updated to 2.5.4 - OpenJDK 7u75 to fix security issues and
  bugs:

  * Security fixes

  - S8046656: Update protocol support

  - S8047125, CVE-2015-0395: (ref) More phantom object references

  - S8047130: Fewer escapes from escape analysis

  - S8048035, CVE-2015-0400: Ensure proper proxy protocols

  - S8049253: Better GC validation

  - S8050807, CVE-2015-0383: Better performing performance data handling

  - S8054367, CVE-2015-0412: More references for endpoints

  - S8055304, CVE-2015-0407: More boxing for DirectoryComboBoxModel

  - S8055309, CVE-2015-0408: RMI needs better transportation considerations

  - S8055479: TLAB stability

  - S8055489, CVE-2014-6585: Better substitution formats

  - S8056264, CVE-2014-6587: Multicast support improvements

  - S8056276, CVE-2014-6591: Fontmanager feature improvements

  - S8057555, CVE-2014-6593: Less cryptic cipher suite management

  - S8058982, CVE-2014-6601: Better verification of an exceptional
  invokespecial

  - S8059485, CVE-2015-0410: Resolve parsing ambiguity

  - S8061210, CVE-2014-3566: Issues in TLS" );
	script_tag( name: "affected", value: "java-1_7_0-openjdk on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:0190-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.2" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk", rpm: "java-1_7_0-openjdk~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-accessibility", rpm: "java-1_7_0-openjdk-accessibility~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap", rpm: "java-1_7_0-openjdk-bootstrap~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-debuginfo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-debugsource", rpm: "java-1_7_0-openjdk-bootstrap-debugsource~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-devel", rpm: "java-1_7_0-openjdk-bootstrap-devel~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-devel-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-devel-debuginfo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-headless", rpm: "java-1_7_0-openjdk-bootstrap-headless~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-bootstrap-headless-debuginfo", rpm: "java-1_7_0-openjdk-bootstrap-headless-debuginfo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debuginfo", rpm: "java-1_7_0-openjdk-debuginfo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-debugsource", rpm: "java-1_7_0-openjdk-debugsource~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo", rpm: "java-1_7_0-openjdk-demo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-demo-debuginfo", rpm: "java-1_7_0-openjdk-demo-debuginfo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel", rpm: "java-1_7_0-openjdk-devel~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-devel-debuginfo", rpm: "java-1_7_0-openjdk-devel-debuginfo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless", rpm: "java-1_7_0-openjdk-headless~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-headless-debuginfo", rpm: "java-1_7_0-openjdk-headless-debuginfo~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-src", rpm: "java-1_7_0-openjdk-src~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_7_0-openjdk-javadoc", rpm: "java-1_7_0-openjdk-javadoc~1.7.0.75~4.1", rls: "openSUSE13.2" ) )){
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

