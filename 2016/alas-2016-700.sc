if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120689" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:08 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-700)" );
	script_tag( name: "insight", value: "Multiple flaws were found in OpenJDK. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update java-1.6.0-openjdk to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-700.html" );
	script_cve_id( "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-0686", "CVE-2016-3427", "CVE-2016-0687" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)" );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-devel", rpm: "java-1.6.0-openjdk-devel~1.6.0.39~1.13.11.1.74.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-debuginfo", rpm: "java-1.6.0-openjdk-debuginfo~1.6.0.39~1.13.11.1.74.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-demo", rpm: "java-1.6.0-openjdk-demo~1.6.0.39~1.13.11.1.74.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-src", rpm: "java-1.6.0-openjdk-src~1.6.0.39~1.13.11.1.74.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk", rpm: "java-1.6.0-openjdk~1.6.0.39~1.13.11.1.74.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "java-1.6.0-openjdk-javadoc", rpm: "java-1.6.0-openjdk-javadoc~1.6.0.39~1.13.11.1.74.amzn1", rls: "AMAZON" ) )){
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

