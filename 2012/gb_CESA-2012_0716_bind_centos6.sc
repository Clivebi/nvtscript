if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-June/018675.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881077" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:01:37 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-1033", "CVE-2012-1667" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:C" );
	script_xref( name: "CESA", value: "2012:0716" );
	script_name( "CentOS Update for bind CESA-2012:0716 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "bind on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
  Name System (DNS) protocols. BIND includes a DNS server (named), a resolver
  library (routines for applications to use when interfacing with DNS), and
  tools for verifying that the DNS server is operating correctly.

  A flaw was found in the way BIND handled zero length resource data records.
  A malicious owner of a DNS domain could use this flaw to create
  specially-crafted DNS resource records that would cause a recursive
  resolver or secondary server to crash or, possibly, disclose portions of
  its memory. (CVE-2012-1667)

  A flaw was found in the way BIND handled the updating of cached name server
  (NS) resource records. A malicious owner of a DNS domain could use this
  flaw to keep the domain resolvable by the BIND server even after the
  delegation was removed from the parent DNS zone. With this update, BIND
  limits the time-to-live of the replacement record to that of the
  time-to-live of the record being replaced. (CVE-2012-1033)

  Users of bind are advised to upgrade to these updated packages, which
  correct these issues. After installing the update, the BIND daemon (named)
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.7.3~8.P3.el6_2.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-chroot", rpm: "bind-chroot~9.7.3~8.P3.el6_2.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.7.3~8.P3.el6_2.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.7.3~8.P3.el6_2.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-sdb", rpm: "bind-sdb~9.7.3~8.P3.el6_2.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.7.3~8.P3.el6_2.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

