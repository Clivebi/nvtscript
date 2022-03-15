if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120398" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 11:24:40 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2011-27)" );
	script_tag( name: "insight", value: "An authentication bypass flaw was found in the cyrus-imapd NNTP server, nntpd. A remote user able to use the nntpd service could use this flaw to read or post newsgroup messages on an NNTP server configured to require user authentication, without providing valid authentication credentials. (CVE-2011-3372 )A NULL pointer dereference flaw was found in the cyrus-imapd IMAP server, imapd. A remote attacker could send a specially-crafted mail message to a victim that would possibly prevent them from accessing their mail normally, if they were using an IMAP client that relies on the server threading IMAP feature. (CVE-2011-3481 )" );
	script_tag( name: "solution", value: "Run yum update cyrus-imapd to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2011-27.html" );
	script_cve_id( "CVE-2011-3372", "CVE-2011-3481" );
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
	if(!isnull( res = isrpmvuln( pkg: "cyrus-imapd", rpm: "cyrus-imapd~2.3.16~6.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-imapd-devel", rpm: "cyrus-imapd-devel~2.3.16~6.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-imapd-utils", rpm: "cyrus-imapd-utils~2.3.16~6.5.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-imapd-debuginfo", rpm: "cyrus-imapd-debuginfo~2.3.16~6.5.amzn1", rls: "AMAZON" ) )){
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

