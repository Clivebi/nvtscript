if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851239" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-03-17 05:11:26 +0100 (Thu, 17 Mar 2016)" );
	script_cve_id( "CVE-2016-2510" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for bsh2 (openSUSE-SU-2016:0788-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bsh2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for bsh2 fixes the following issues:

  - CVE-2016-2510: An application that includes BeanShell on the classpath
  may be vulnerable if another part of the application uses Java
  serialization or XStream to deserialize data from an untrusted source.

  This update was imported from the SUSE:SLE-12:Update update project." );
	script_tag( name: "affected", value: "bsh2 on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0788-1" );
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
	if(!isnull( res = isrpmvuln( pkg: "bsh2", rpm: "bsh2~2.0.0.b5~30.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bsh2-bsf", rpm: "bsh2-bsf~2.0.0.b5~30.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bsh2-classgen", rpm: "bsh2-classgen~2.0.0.b5~30.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bsh2-demo", rpm: "bsh2-demo~2.0.0.b5~30.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bsh2-javadoc", rpm: "bsh2-javadoc~2.0.0.b5~30.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bsh2-manual", rpm: "bsh2-manual~2.0.0.b5~30.1", rls: "openSUSELeap42.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "bsh2-src", rpm: "sh2-src~2.0.0.b5~30.1", rls: "openSUSELeap42.1" ) )){
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

