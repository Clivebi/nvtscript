if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120724" );
	script_version( "2021-09-20T12:38:59+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:20 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 12:38:59 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-735)" );
	script_tag( name: "insight", value: "A buffer overflow flaw was found in the way the Squid cachemgr.cgi utility processed remotely relayed Squid input. When the CGI interface utility is used, a remote attacker could possibly use this flaw to execute arbitrary code. (CVE-2016-4051 )It was found that the fix for CVE-2016-4051  did not properly prevent the stack overflow in the munge_other_line() function. A remote attacker could send specially crafted data to the Squid proxy, which would exploit the cachemgr CGI utility, possibly triggering execution of arbitrary code. (CVE-2016-5408 )" );
	script_tag( name: "solution", value: "Run yum update squid to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-735.html" );
	script_cve_id( "CVE-2016-4051", "CVE-2016-5408" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
	if(!isnull( res = isrpmvuln( pkg: "squid", rpm: "squid~3.1.23~16.22.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "squid-debuginfo", rpm: "squid-debuginfo~3.1.23~16.22.amzn1", rls: "AMAZON" ) )){
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

