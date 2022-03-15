if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-October/018106.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881263" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:13:36 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-1091", "CVE-2011-3594" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:1371" );
	script_name( "CentOS Update for finch CESA-2011:1371 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'finch'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "finch on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  An input sanitization flaw was found in the way the Pidgin SILC (Secure
  Internet Live Conferencing) protocol plug-in escaped certain UTF-8
  characters. A remote attacker could use this flaw to crash Pidgin via a
  specially-crafted SILC message. (CVE-2011-3594)

  Multiple NULL pointer dereference flaws were found in the way the Pidgin
  Yahoo! Messenger Protocol plug-in handled malformed YMSG packets. A remote
  attacker could use these flaws to crash Pidgin via a specially-crafted
  notification message. (CVE-2011-1091)

  Red Hat would like to thank the Pidgin project for reporting CVE-2011-1091.
  Upstream acknowledges Marius Wachtler as the original reporter of
  CVE-2011-1091.

  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect." );
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
	if(( res = isrpmvuln( pkg: "finch", rpm: "finch~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "finch-devel", rpm: "finch-devel~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple", rpm: "libpurple~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple-devel", rpm: "libpurple-devel~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple-perl", rpm: "libpurple-perl~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple-tcl", rpm: "libpurple-tcl~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin", rpm: "pidgin~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin-devel", rpm: "pidgin-devel~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin-perl", rpm: "pidgin-perl~2.6.6~5.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
