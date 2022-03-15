if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120453" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:26:43 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-467)" );
	script_tag( name: "insight", value: "A flaw was found in the way mailx handled the parsing of email addresses. A syntactically valid email address could allow a local attacker to cause mailx to execute arbitrary shell commands through shell meta-characters and the direct command execution functionality. (CVE-2004-2771, CVE-2014-7844 )Note: Applications using mailx to send email to addresses obtained from untrusted sources will still remain vulnerable to other attacks if they accept email addresses which start with - (so that they can be confused with mailx options). To counteract this issue, this update also introduces the -- option, which will treat the remaining command line arguments as email addresses." );
	script_tag( name: "solution", value: "Run yum update mailx to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-467.html" );
	script_cve_id( "CVE-2004-2771", "CVE-2014-7844" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "mailx", rpm: "mailx~12.4~8.8.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mailx-debuginfo", rpm: "mailx-debuginfo~12.4~8.8.amzn1", rls: "AMAZON" ) )){
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

