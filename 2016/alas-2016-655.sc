if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120645" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-03-08 07:12:17 +0200 (Tue, 08 Mar 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-655)" );
	script_tag( name: "insight", value: "It was discovered that nginx could perform an out of bound read and dereference an invalid pointer when resolving CNAME DNS records. An attacker able to manipulate DNS responses received by nginx could use this flaw to cause a worker process to crash if nginx enabled the resolver in its configuration. (CVE-2016-0742 )A use-after-free flaw was found in the way nginx resolved certain CNAME DNS records. An attacker able to manipulate DNS responses received by nginx could use this flaw to cause a worker process to crash or, possibly, execute arbitrary code if nginx enabled the resolver in its configuration. (CVE-2016-0746 )It was discovered that nginx did not limit recursion when resolving CNAME DNS records. An attacker able to manipulate DNS responses received by nginx could use this flaw to cause a worker process to use an excessive amount of resources if nginx enabled the resolver in its configuration. (CVE-2016-0747 )" );
	script_tag( name: "solution", value: "Run yum update nginx to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-655.html" );
	script_cve_id( "CVE-2016-0747", "CVE-2016-0746", "CVE-2016-0742" );
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
	if(!isnull( res = isrpmvuln( pkg: "nginx", rpm: "nginx~1.8.1~1.26.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nginx-debuginfo", rpm: "nginx-debuginfo~1.8.1~1.26.amzn1", rls: "AMAZON" ) )){
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

