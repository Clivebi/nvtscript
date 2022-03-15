if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-October/016220.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880864" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2009:1459" );
	script_cve_id( "CVE-2009-2632", "CVE-2009-3235" );
	script_name( "CentOS Update for cyrus-imapd CESA-2009:1459 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cyrus-imapd'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "cyrus-imapd on CentOS 5" );
	script_tag( name: "insight", value: "The cyrus-imapd packages contain a high-performance mail server with IMAP,
  POP3, NNTP, and Sieve support.

  Multiple buffer overflow flaws were found in the Cyrus IMAP Sieve
  implementation. An authenticated user able to create Sieve mail filtering
  rules could use these flaws to execute arbitrary code with the privileges
  of the Cyrus IMAP server user. (CVE-2009-2632, CVE-2009-3235)

  Users of cyrus-imapd are advised to upgrade to these updated packages,
  which contain backported patches to resolve these issues. After installing
  the update, cyrus-imapd will be restarted automatically." );
	script_tag( name: "solution", value: "Please install the updated packages." );
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
	if(( res = isrpmvuln( pkg: "cyrus-imapd", rpm: "cyrus-imapd~2.3.7~7.el5_4.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cyrus-imapd-devel", rpm: "cyrus-imapd-devel~2.3.7~7.el5_4.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cyrus-imapd-perl", rpm: "cyrus-imapd-perl~2.3.7~7.el5_4.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "cyrus-imapd-utils", rpm: "cyrus-imapd-utils~2.3.7~7.el5_4.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

