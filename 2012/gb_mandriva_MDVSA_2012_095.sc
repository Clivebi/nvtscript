if(description){
	script_xref( name: "URL", value: "http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:095" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831669" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-03 09:59:45 +0530 (Fri, 03 Aug 2012)" );
	script_cve_id( "CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "MDVSA", value: "2012:095" );
	script_name( "Mandriva Update for java-1.6.0-openjdk MDVSA-2012:095 (java-1.6.0-openjdk)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(2011\\.0|mes5\\.2|2010\\.1)" );
	script_tag( name: "affected", value: "java-1.6.0-openjdk on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2,
  Mandriva Linux 2010.1" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Multiple security issues were identified and fixed in OpenJDK
  (icedtea6):

  * S7079902, CVE-2012-1711: Refine CORBA data models

  * S7143617, CVE-2012-1713: Improve fontmanager layout lookup operations

  * S7143614, CVE-2012-1716: SynthLookAndFeel stability improvement

  * S7143606, CVE-2012-1717: File.createTempFile should be improved
  for temporary files created by the platform.

  * S7143872, CVE-2012-1718: Improve certificate extension processing

  * S7143851, CVE-2012-1719: Improve IIOP stub and tie generation in RMIC

  * S7152811, CVE-2012-1723: Issues in client compiler

  * S7157609, CVE-2012-1724: Issues with loop

  * S7160757, CVE-2012-1725: Problem with hotspot/runtime_classfile

  * S7110720: Issue with vm config file loadingIssue with vm config
  file loading

  * S7145239: Finetune package definition restriction

  * S7160677: missing else in fix for 7152811

  The updated packages provides icedtea6-1.11.3 which is not vulnerable
  to these issues." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_2011.0"){
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.0~26.b24.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-demo", rpm: "java-1.6.0-openjdk-demo~1.6.0.0~26.b24.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-devel", rpm: "java-1.6.0-openjdk-devel~1.6.0.0~26.b24.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-javadoc", rpm: "java-1.6.0-openjdk-javadoc~1.6.0.0~26.b24.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.0~26.b24.1", rls: "MNDK_2011.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_mes5.2"){
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.0~26.b24.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-demo", rpm: "java-1.6.0-openjdk-demo~1.6.0.0~26.b24.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-devel", rpm: "java-1.6.0-openjdk-devel~1.6.0.0~26.b24.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-javadoc", rpm: "java-1.6.0-openjdk-javadoc~1.6.0.0~26.b24.1mdvmes5.2", rls: "MNDK_mes5.2" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.0~26.b24.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-demo", rpm: "java-1.6.0-openjdk-demo~1.6.0.0~26.b24.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-devel", rpm: "java-1.6.0-openjdk-devel~1.6.0.0~26.b24.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "java-1.6.0-openjdk-javadoc", rpm: "java-1.6.0-openjdk-javadoc~1.6.0.0~26.b24.1mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

