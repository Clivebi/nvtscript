if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120611" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-12-15 02:51:23 +0200 (Tue, 15 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-621)" );
	script_tag( name: "insight", value: "An integer overflow flaw was found in the way the buffer() function handled its offset and size arguments. An attacker able to control those arguments could use this flaw to disclose portions of the application memory or cause it to crash.It was discovered that multiple Python standard library modules implementing network protocols (such as httplib or smtplib) failed to restrict sizes of server responses. A malicious server could cause a client using one of the affected modules to consume an excessive amount of memory.It was discovered that the CGIHTTPServer module incorrectly handled URL encoded paths. A remote attacker could use this flaw to execute scripts outside of the cgi-bin directory, or disclose source of scripts in the cgi-bin directory." );
	script_tag( name: "solution", value: "Run yum update python26 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-621.html" );
	script_cve_id( "CVE-2014-7185", "CVE-2013-1752", "CVE-2014-4650" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "python26-test", rpm: "python26-test~2.6.9~2.83.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python26-tools", rpm: "python26-tools~2.6.9~2.83.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python26-debuginfo", rpm: "python26-debuginfo~2.6.9~2.83.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python26-libs", rpm: "python26-libs~2.6.9~2.83.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python26-devel", rpm: "python26-devel~2.6.9~2.83.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python26", rpm: "python26~2.6.9~2.83.amzn1", rls: "AMAZON" ) )){
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

