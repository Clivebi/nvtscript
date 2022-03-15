if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120234" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:21:01 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-156)" );
	script_tag( name: "insight", value: "Multiple flaws were found in OpenJDK. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update java-1.7.0-openjdk to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-156.html" );
	script_cve_id( "CVE-2013-1478", "CVE-2013-0440", "CVE-2013-0443", "CVE-2013-0442", "CVE-2013-0431", "CVE-2013-0432", "CVE-2013-0424", "CVE-2013-0435", "CVE-2013-0445", "CVE-2013-0441", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-0429", "CVE-2013-0450", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0428", "CVE-2013-0444", "CVE-2013-1480", "CVE-2013-0427", "CVE-2013-0433", "CVE-2013-0434" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk-demo", rpm: "java-1.7.0-openjdk-demo~1.7.0.9~2.3.5.3.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk-devel", rpm: "java-1.7.0-openjdk-devel~1.7.0.9~2.3.5.3.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk-debuginfo", rpm: "java-1.7.0-openjdk-debuginfo~1.7.0.9~2.3.5.3.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk-src", rpm: "java-1.7.0-openjdk-src~1.7.0.9~2.3.5.3.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk", rpm: "java-1.7.0-openjdk~1.7.0.9~2.3.5.3.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.7.0-openjdk-javadoc", rpm: "java-1.7.0-openjdk-javadoc~1.7.0.9~2.3.5.3.17.amzn1", rls: "AMAZON" ) )){
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

