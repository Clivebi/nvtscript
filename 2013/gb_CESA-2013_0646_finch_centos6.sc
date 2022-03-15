if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019648.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881691" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-15 09:53:27 +0530 (Fri, 15 Mar 2013)" );
	script_cve_id( "CVE-2013-0272", "CVE-2013-0273", "CVE-2013-0274" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2013:0646" );
	script_name( "CentOS Update for finch CESA-2013:0646 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'finch'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "finch on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  A stack-based buffer overflow flaw was found in the Pidgin MXit protocol
  plug-in. A malicious server or a remote attacker could use this flaw to
  crash Pidgin by sending a specially-crafted HTTP request. (CVE-2013-0272)

  A buffer overflow flaw was found in the Pidgin Sametime protocol plug-in.
  A malicious server or a remote attacker could use this flaw to crash Pidgin
  by sending a specially-crafted username. (CVE-2013-0273)

  A buffer overflow flaw was found in the way Pidgin processed certain UPnP
  responses. A remote attacker could send a specially-crafted UPnP response
  that, when processed, would crash Pidgin. (CVE-2013-0274)

  Red Hat would like to thank the Pidgin project for reporting the above
  issues. Upstream acknowledges Daniel Atallah as the original reporter of
  CVE-2013-0272.

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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "finch", rpm: "finch~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "finch-devel", rpm: "finch-devel~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple", rpm: "libpurple~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple-devel", rpm: "libpurple-devel~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple-perl", rpm: "libpurple-perl~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "libpurple-tcl", rpm: "libpurple-tcl~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin", rpm: "pidgin~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin-devel", rpm: "pidgin-devel~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin-docs", rpm: "pidgin-docs~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "pidgin-perl", rpm: "pidgin-perl~2.7.9~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

