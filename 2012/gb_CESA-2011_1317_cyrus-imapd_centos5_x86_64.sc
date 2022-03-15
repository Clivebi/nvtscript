if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-September/017747.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881255" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:12:57 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-3208" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:1317" );
	script_name( "CentOS Update for cyrus-imapd CESA-2011:1317 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cyrus-imapd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "cyrus-imapd on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The cyrus-imapd packages contain a high-performance mail server with IMAP,
  POP3, NNTP, and Sieve support.

  A buffer overflow flaw was found in the cyrus-imapd NNTP server, nntpd. A
  remote user able to use the nntpd service could use this flaw to crash the
  nntpd child process or, possibly, execute arbitrary code with the
  privileges of the cyrus user. (CVE-2011-3208)

  Red Hat would like to thank Greg Banks for reporting this issue.

  Users of cyrus-imapd are advised to upgrade to these updated packages,
  which contain a backported patch to correct this issue. After installing
  the update, cyrus-imapd will be restarted automatically." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "cyrus-imapd", rpm: "cyrus-imapd~2.3.7~12.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cyrus-imapd-devel", rpm: "cyrus-imapd-devel~2.3.7~12.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cyrus-imapd-perl", rpm: "cyrus-imapd-perl~2.3.7~12.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cyrus-imapd-utils", rpm: "cyrus-imapd-utils~2.3.7~12.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

