if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120671" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-03-31 08:02:14 +0300 (Thu, 31 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-681)" );
	script_tag( name: "insight", value: "Multiple flaws were found in Apache Tomcat. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update tomcat6 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-681.html" );
	script_cve_id( "CVE-2015-5174", "CVE-2015-5345", "CVE-2016-0714", "CVE-2016-0706" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-jsp-2.1-api", rpm: "tomcat6-jsp-2.1-api~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6", rpm: "tomcat6~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-admin-webapps", rpm: "tomcat6-admin-webapps~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-servlet-2.5-api", rpm: "tomcat6-servlet-2.5-api~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-docs-webapp", rpm: "tomcat6-docs-webapp~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-el-2.1-api", rpm: "tomcat6-el-2.1-api~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-webapps", rpm: "tomcat6-webapps~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-lib", rpm: "tomcat6-lib~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-javadoc", rpm: "tomcat6-javadoc~6.0.45~1.4.amzn1", rls: "AMAZON" ) )){
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

