if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-May/017600.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881251" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:11:57 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-1910" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0845" );
	script_name( "CentOS Update for bind97 CESA-2011:0845 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind97'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "bind97 on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named), a resolver
  library (routines for applications to use when interfacing with DNS), and
  tools for verifying that the DNS server is operating correctly.

  An off-by-one flaw was found in the way BIND processed negative responses
  with large resource record sets (RRSets). An attacker able to send
  recursive queries to a BIND server that is configured as a caching
  resolver could use this flaw to cause named to exit with an assertion
  failure. (CVE-2011-1910)

  All BIND users are advised to upgrade to these updated packages, which
  resolve this issue. After installing the update, the BIND daemon (named)
  will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "bind97", rpm: "bind97~9.7.0~6.P2.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-chroot", rpm: "bind97-chroot~9.7.0~6.P2.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-devel", rpm: "bind97-devel~9.7.0~6.P2.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-libs", rpm: "bind97-libs~9.7.0~6.P2.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind97-utils", rpm: "bind97-utils~9.7.0~6.P2.el5_6.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

