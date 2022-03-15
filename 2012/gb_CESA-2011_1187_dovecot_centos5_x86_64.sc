if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-September/017808.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881402" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:46:30 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-1929" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:1187" );
	script_name( "CentOS Update for dovecot CESA-2011:1187 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "dovecot on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Dovecot is an IMAP server for Linux, UNIX, and similar operating systems,
  primarily written with security in mind.

  A denial of service flaw was found in the way Dovecot handled NULL
  characters in certain header names. A mail message with specially-crafted
  headers could cause the Dovecot child process handling the target user's
  connection to crash, blocking them from downloading the message
  successfully and possibly leading to the corruption of their mailbox.
  (CVE-2011-1929)

  Users of dovecot are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing the
  updated packages, the dovecot service will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "dovecot", rpm: "dovecot~1.0.7~7.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

