if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120214" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:20:34 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-325)" );
	script_tag( name: "insight", value: "It was found that the secure processing feature of Xalan-Java had insufficient restrictions defined for certain properties and features. A remote attacker able to provide Extensible Stylesheet Language Transformations (XSLT) content to be processed by an application using Xalan-Java could use this flaw to bypass the intended constraints of the secure processing feature. Depending on the components available in the classpath, this could lead to arbitrary remote code execution in the context of the application server running the application that uses Xalan-Java. (CVE-2014-0107 )" );
	script_tag( name: "solution", value: "Run yum update xalan-j2 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-325.html" );
	script_cve_id( "CVE-2014-0107" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "xalan-j2-demo", rpm: "xalan-j2-demo~2.7.0~9.9.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xalan-j2-javadoc", rpm: "xalan-j2-javadoc~2.7.0~9.9.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xalan-j2", rpm: "xalan-j2~2.7.0~9.9.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xalan-j2-manual", rpm: "xalan-j2-manual~2.7.0~9.9.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xalan-j2-xsltc", rpm: "xalan-j2-xsltc~2.7.0~9.9.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xalan-j2", rpm: "xalan-j2~2.7.0~9.9.9.amzn1", rls: "AMAZON" ) )){
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

