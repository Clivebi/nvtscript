if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120268" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:21:59 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-105)" );
	script_tag( name: "insight", value: "A numeric truncation error, leading to a heap-based buffer overflow, was found in the way the rsyslog imfile module processed text files containing long lines. An attacker could use this flaw to crash the rsyslogd daemon or, possibly, execute arbitrary code with the privileges of rsyslogd, if they are able to cause a long line to be written to a log file that rsyslogd monitors with imfile. The imfile module is not enabled by default. (CVE-2011-4623 )" );
	script_tag( name: "solution", value: "Run yum update rsyslog to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-105.html" );
	script_cve_id( "CVE-2011-4623" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-gssapi", rpm: "rsyslog-gssapi~5.8.10~2.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-snmp", rpm: "rsyslog-snmp~5.8.10~2.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-mysql", rpm: "rsyslog-mysql~5.8.10~2.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-pgsql", rpm: "rsyslog-pgsql~5.8.10~2.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog", rpm: "rsyslog~5.8.10~2.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-gnutls", rpm: "rsyslog-gnutls~5.8.10~2.17.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rsyslog-debuginfo", rpm: "rsyslog-debuginfo~5.8.10~2.17.amzn1", rls: "AMAZON" ) )){
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

