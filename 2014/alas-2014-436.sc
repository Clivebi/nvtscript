if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120345" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:24:16 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-436)" );
	script_tag( name: "insight", value: "A resource consumption issue was found in the way Xerces-J handled XML declarations. A remote attacker could use an XML document with a specially crafted declaration using a long pseudo-attribute name that, when parsed by an application using Xerces-J, would cause that application to use an excessive amount of CPU." );
	script_tag( name: "solution", value: "Run yum update xerces-j2 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-436.html" );
	script_cve_id( "CVE-2013-4002" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2-javadoc-apis", rpm: "xerces-j2-javadoc-apis~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2-javadoc-xni", rpm: "xerces-j2-javadoc-xni~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2-javadoc-other", rpm: "xerces-j2-javadoc-other~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2-demo", rpm: "xerces-j2-demo~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2", rpm: "xerces-j2~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2-scripts", rpm: "xerces-j2-scripts~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2-javadoc-impl", rpm: "xerces-j2-javadoc-impl~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xerces-j2", rpm: "xerces-j2~2.7.1~12.7.19.amzn1", rls: "AMAZON" ) )){
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

