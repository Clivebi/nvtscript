if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.850672" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-09-18 10:28:17 +0200 (Fri, 18 Sep 2015)" );
	script_cve_id( "CVE-2015-2590", "CVE-2015-2597", "CVE-2015-2601", "CVE-2015-2613", "CVE-2015-2619", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2627", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2637", "CVE-2015-2638", "CVE-2015-2659", "CVE-2015-2664", "CVE-2015-2808", "CVE-2015-4000", "CVE-2015-4729", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4736", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for java-1_8_0-openjdk (openSUSE-SU-2015:1289-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1_8_0-openjdk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "OpenJDK was updated to 2.6.1 - OpenJDK 8u51 to fix security issues and
  bugs.

  The following vulnerabilities were fixed:

  * CVE-2015-2590: Easily exploitable vulnerability in the Libraries
  component allowed successful unauthenticated network attacks via
  multiple protocols. Successful attack of this vulnerability could have
  resulted in unauthorized Operating System takeover including arbitrary
  code execution.

  * CVE-2015-2597: Easily exploitable vulnerability in the Install component
  requiring logon to Operating System. Successful attack of this
  vulnerability could have resulted in unauthorized Operating System
  takeover including arbitrary code execution.

  * CVE-2015-2601: Easily exploitable vulnerability in the JCE component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2613: Easily exploitable vulnerability in the JCE component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java SE, Java SE Embedded
  accessible data.

  * CVE-2015-2619: Easily exploitable vulnerability in the 2D component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2621: Easily exploitable vulnerability in the JMX component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2625: Very difficult to exploit vulnerability in the JSSE
  component allowed successful unauthenticated network attacks via
  SSL/TLS. Successful attack of this vulnerability could have resulted in
  unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2627: Very difficult to exploit vulnerability in the Install
  component allowed successful unauthenticated network attacks via
  multiple protocols. Successful attack of this vulnerability could have
  resulted in unauthorized read access to a subset of Java accessible data.

  * CVE-2015-2628: Easily exploitable vulnerability in the CORBA component
  allowed successful unauthenticated network attacks via multiple
  protocols. Successful attack of this vulnerability could have resulted
  in unauthorized Opera ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "java-1_8_0-openjdk on openSUSE 13.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2015:1289-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk", rpm: "java-1_8_0-openjdk~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-accessibility", rpm: "java-1_8_0-openjdk-accessibility~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debuginfo", rpm: "java-1_8_0-openjdk-debuginfo~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-debugsource", rpm: "java-1_8_0-openjdk-debugsource~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo", rpm: "java-1_8_0-openjdk-demo~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-demo-debuginfo", rpm: "java-1_8_0-openjdk-demo-debuginfo~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-devel", rpm: "java-1_8_0-openjdk-devel~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless", rpm: "java-1_8_0-openjdk-headless~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-headless-debuginfo", rpm: "java-1_8_0-openjdk-headless-debuginfo~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-src", rpm: "java-1_8_0-openjdk-src~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1_8_0-openjdk-javadoc", rpm: "java-1_8_0-openjdk-javadoc~1.8.0.51~12.1", rls: "openSUSE13.2" ) )){
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

