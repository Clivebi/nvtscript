if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120647" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-03-11 07:09:11 +0200 (Fri, 11 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-657)" );
	script_tag( name: "insight", value: "A directory traversal vulnerability in RequestUtil.java was discovered which allows remote authenticated users to bypass intended SecurityManager restrictions and list a parent directory via a /.. (slash dot dot) in a pathname used by a web application in a getResource, getResourceAsStream, or getResourcePaths call. (CVE-2015-5174 )A session fixation vulnerability was discovered that might allow remote attackers to hijack web sessions by leveraging use of a requestedSessionSSL field for an unintended request when different session settings are used for deployments of multiple versions of the same web application. (CVE-2015-5346 )It was found that the expression language resolver evaluated expressions within a privileged code section. A malicious web application could use this flaw to bypass security manager protections. (CVE-2014-7810 )" );
	script_tag( name: "solution", value: "Run yum update tomcat7 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-657.html" );
	script_cve_id( "CVE-2015-5174", "CVE-2015-5346", "CVE-2014-7810" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-el-2.2-api", rpm: "tomcat7-el-2.2-api~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-log4j", rpm: "tomcat7-log4j~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7", rpm: "tomcat7~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-docs-webapp", rpm: "tomcat7-docs-webapp~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-webapps", rpm: "tomcat7-webapps~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-admin-webapps", rpm: "tomcat7-admin-webapps~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-lib", rpm: "tomcat7-lib~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-jsp-2.2-api", rpm: "tomcat7-jsp-2.2-api~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-servlet-3.0-api", rpm: "tomcat7-servlet-3.0-api~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat7-javadoc", rpm: "tomcat7-javadoc~7.0.67~1.13.amzn1", rls: "AMAZON" ) )){
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

