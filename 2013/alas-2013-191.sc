if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120303" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:23:10 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-191)" );
	script_tag( name: "insight", value: "java/org/apache/catalina/core/AsyncContextImpl.java in Apache Tomcat 7.x before 7.0.40 does not properly handle the throwing of a RuntimeException in an AsyncListener in an application, which allows context-dependent attackers to obtain sensitive request information intended for other applications in opportunistic circumstances via an application that records the requests that it processes." );
	script_tag( name: "solution", value: "Run yum update tomcat7 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-191.html" );
	script_cve_id( "CVE-2013-2071" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
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
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-lib", rpm: "tomcat7-lib~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-jsp-2.2-api", rpm: "tomcat7-jsp-2.2-api~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-webapps", rpm: "tomcat7-webapps~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-javadoc", rpm: "tomcat7-javadoc~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-docs-webapp", rpm: "tomcat7-docs-webapp~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-admin-webapps", rpm: "tomcat7-admin-webapps~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-el-2.2-api", rpm: "tomcat7-el-2.2-api~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7", rpm: "tomcat7~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-servlet-3.0-api", rpm: "tomcat7-servlet-3.0-api~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7", rpm: "tomcat7~7.0.40~1.26.amzn1", rls: "AMAZON" ) )){
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

