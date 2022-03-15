if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120134" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:18:19 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-89)" );
	script_tag( name: "insight", value: "A denial of service flaw was found in the implementation of hash arrays in Expat. An attacker could use this flaw to make an application using Expat consume an excessive amount of CPU time by providing a specially-crafted XML file that triggers multiple hash function collisions. To mitigate this issue, randomization has been added to the hash function to reduce the chance of an attacker successfully causing intentional collisions. (CVE-2012-0876 )A memory leak flaw was found in Expat. If an XML file processed by an application linked against Expat triggered a memory re-allocation failure, Expat failed to free the previously allocated memory. This could cause the application to exit unexpectedly or crash when all available memory is exhausted. (CVE-2012-1148 )" );
	script_tag( name: "solution", value: "Run yum update expat to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-89.html" );
	script_cve_id( "CVE-2012-1148", "CVE-2012-0876" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "expat-devel", rpm: "expat-devel~2.0.1~11.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat-debuginfo", rpm: "expat-debuginfo~2.0.1~11.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "expat", rpm: "expat~2.0.1~11.9.amzn1", rls: "AMAZON" ) )){
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

