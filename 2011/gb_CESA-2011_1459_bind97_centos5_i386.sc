if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-November/018209.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881044" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-11-21 09:35:58 +0530 (Mon, 21 Nov 2011)" );
	script_xref( name: "CESA", value: "2011:1459" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2011-4313" );
	script_name( "CentOS Update for bind97 CESA-2011:1459 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind97'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "bind97 on CentOS 5" );
	script_tag( name: "insight", value: "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named), a resolver
  library (routines for applications to use when interfacing with DNS), and
  tools for verifying that the DNS server is operating correctly.

  A flaw was discovered in the way BIND handled certain DNS queries, which
  caused it to cache an invalid record. A remote attacker could use this
  flaw to send repeated queries for this invalid record, causing the
  resolvers to exit unexpectedly due to a failed assertion. (CVE-2011-4313)

  Users of bind97 are advised to upgrade to these updated packages, which
  resolve this issue. After installing the update, the BIND daemon (named)
  will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "bind97", rpm: "bind97~9.7.0~6.P2.el5_7.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-chroot", rpm: "bind97-chroot~9.7.0~6.P2.el5_7.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-devel", rpm: "bind97-devel~9.7.0~6.P2.el5_7.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-libs", rpm: "bind97-libs~9.7.0~6.P2.el5_7.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-utils", rpm: "bind97-utils~9.7.0~6.P2.el5_7.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

