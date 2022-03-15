if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120737" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:25 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-748)" );
	script_tag( name: "insight", value: "An insufficient bytecode verification flaw was discovered in the Hotspot component in OpenJDK. An untrusted Java application or applet could use this flaw to completely bypass Java sandbox restrictions. (CVE-2016-3606 )Multiple denial of service flaws were found in the JAXP component in OpenJDK. A specially crafted XML file could cause a Java application using JAXP to consume an excessive amount of CPU and memory when parsed. (CVE-2016-3500, CVE-2016-3508 )Multiple flaws were found in the CORBA and Hotsport components in OpenJDK. An untrusted Java application or applet could use these flaws to bypass certain Java sandbox restrictions. (CVE-2016-3458, CVE-2016-3550 )" );
	script_tag( name: "solution", value: "Run yum update java-1.6.0-openjdk to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-748.html" );
	script_cve_id( "CVE-2016-3550", "CVE-2016-3606", "CVE-2016-3458", "CVE-2016-3500", "CVE-2016-3508" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-src", rpm: "java-1.6.0-openjdk-src~1.6.0.40~1.13.12.6.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-javadoc", rpm: "java-1.6.0-openjdk-javadoc~1.6.0.40~1.13.12.6.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-demo", rpm: "java-1.6.0-openjdk-demo~1.6.0.40~1.13.12.6.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-debuginfo", rpm: "java-1.6.0-openjdk-debuginfo~1.6.0.40~1.13.12.6.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-devel", rpm: "java-1.6.0-openjdk-devel~1.6.0.40~1.13.12.6.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.40~1.13.12.6.75.amzn1", rls: "AMAZON" ) )){
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

