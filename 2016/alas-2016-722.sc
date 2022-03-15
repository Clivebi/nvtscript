if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120711" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:15 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-722)" );
	script_tag( name: "insight", value: "Tomcat's CGI support used the value of the Proxy header from HTTP requests to initialize the HTTP_PROXY environment variable for CGI scripts, which in turn was incorrectly used by certain HTTP client implementations to configure the proxy for outgoing HTTP requests. A remote attacker could possibly use this flaw to redirect HTTP requests performed by a CGI script to an attacker-controlled proxy via a malicious HTTP request (known as the httpoxy class of vulnerabilities)." );
	script_tag( name: "solution", value: "Run yum update tomcat6 to update your system.

  Run yum update tomcat7 to update your system.

  Run yum update tomcat8 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-722.html" );
	script_cve_id( "CVE-2016-5388" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-lib", rpm: "tomcat6-lib~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-servlet-2.5-api", rpm: "tomcat6-servlet-2.5-api~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-admin-webapps", rpm: "tomcat6-admin-webapps~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-webapps", rpm: "tomcat6-webapps~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-docs-webapp", rpm: "tomcat6-docs-webapp~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-jsp-2.1-api", rpm: "tomcat6-jsp-2.1-api~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-el-2.1-api", rpm: "tomcat6-el-2.1-api~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-javadoc", rpm: "tomcat6-javadoc~6.0.45~1.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-el-2.2-api", rpm: "tomcat7-el-2.2-api~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-admin-webapps", rpm: "tomcat7-admin-webapps~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-log4j", rpm: "tomcat7-log4j~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-lib", rpm: "tomcat7-lib~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-javadoc", rpm: "tomcat7-javadoc~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-webapps", rpm: "tomcat7-webapps~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-docs-webapp", rpm: "tomcat7-docs-webapp~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-servlet-3.0-api", rpm: "tomcat7-servlet-3.0-api~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-jsp-2.2-api", rpm: "tomcat7-jsp-2.2-api~7.0.69~1.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-jsp-2.3-api", rpm: "tomcat8-jsp-2.3-api~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-javadoc", rpm: "tomcat8-javadoc~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-admin-webapps", rpm: "tomcat8-admin-webapps~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-lib", rpm: "tomcat8-lib~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-servlet-3.1-api", rpm: "tomcat8-servlet-3.1-api~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-el-3.0-api", rpm: "tomcat8-el-3.0-api~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-webapps", rpm: "tomcat8-webapps~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-docs-webapp", rpm: "tomcat8-docs-webapp~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat8-log4j", rpm: "tomcat8-log4j~8.0.35~1.61.amzn1", rls: "AMAZON" ) )){
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

