if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120265" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-25 11:18:00 +0300 (Fri, 25 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-598)" );
	script_tag( name: "insight", value: "An integer overflow flaw, leading to a heap-based buffer overflow, was found in the way grep parsed large lines of data. An attacker able to trick a user into running grep on a specially crafted data file could use this flaw to crash grep or, potentially, execute arbitrary code with the privileges of the user running grep. (CVE-2012-5667 )A heap-based buffer overflow flaw was found in the way grep processed certain pattern and text combinations. An attacker able to trick a user into running grep on specially crafted input could use this flaw to crash grep or, potentially, read from uninitialized memory. (CVE-2015-1345 )" );
	script_tag( name: "solution", value: "Run yum update grep to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-598.html" );
	script_cve_id( "CVE-2012-5667", "CVE-2015-1345" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "grep", rpm: "grep~2.20~1.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grep-debuginfo", rpm: "grep-debuginfo~2.20~1.14.amzn1", rls: "AMAZON" ) )){
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

