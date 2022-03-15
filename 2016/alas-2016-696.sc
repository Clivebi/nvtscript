if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120685" );
	script_version( "2021-09-17T12:01:50+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:12:01 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 12:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-696)" );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in Graphite2. An attacker able to trick an unsuspecting user into opening specially crafted font files in an application using Graphite2 could exploit these flaws to cause the application to crash or, potentially, execute arbitrary code with the privileges of the application." );
	script_tag( name: "solution", value: "Run yum update graphite2 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-696.html" );
	script_cve_id( "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1521", "CVE-2016-1526" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)" );
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
	if(!isnull( res = isrpmvuln( pkg: "graphite2-debuginfo", rpm: "graphite2-debuginfo~1.3.6~1.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphite2", rpm: "graphite2~1.3.6~1.9.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "graphite2-devel", rpm: "graphite2-devel~1.3.6~1.9.amzn1", rls: "AMAZON" ) )){
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

