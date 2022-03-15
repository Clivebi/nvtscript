if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120680" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:11:55 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-690)" );
	script_tag( name: "insight", value: "It was discovered that foomatic-rip failed to remove all shell special characters from inputs used to construct command lines for external programs run by the filter. An attacker could possibly use this flaw to execute arbitrary commands. (CVE-2015-8560 )It was discovered that the unhtmlify() function of foomatic-rip did not correctly calculate buffer sizes, possibly leading to a heap-based memory corruption. A malicious attacker could exploit this flaw to cause foomatic-rip to crash or, possibly, execute arbitrary code. (CVE-2010-5325 )" );
	script_tag( name: "solution", value: "Run yum update foomatic to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-690.html" );
	script_cve_id( "CVE-2015-8560", "CVE-2010-5325" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "foomatic-debuginfo", rpm: "foomatic-debuginfo~4.0.4~5.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "foomatic", rpm: "foomatic~4.0.4~5.11.amzn1", rls: "AMAZON" ) )){
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

