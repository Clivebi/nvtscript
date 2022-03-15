if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-August/018784.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881456" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-08-03 11:16:42 +0530 (Fri, 03 Aug 2012)" );
	script_cve_id( "CVE-2012-3429" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2012:1139" );
	script_name( "CentOS Update for bind-dyndb-ldap CESA-2012:1139 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind-dyndb-ldap'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "bind-dyndb-ldap on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The dynamic LDAP back end is a plug-in for BIND that provides back-end
  capabilities to LDAP databases. It features support for dynamic updates and
  internal caching that help to reduce the load on LDAP servers.

  A flaw was found in the way bind-dyndb-ldap performed the escaping of names
  from DNS requests for use in LDAP queries. A remote attacker able to send
  DNS queries to a named server that is configured to use bind-dyndb-ldap
  could use this flaw to cause named to exit unexpectedly with an assertion
  failure. (CVE-2012-3429)

  Red Hat would like to thank Sigbjorn Lie of Atea Norway for reporting this
  issue.

  All bind-dyndb-ldap users should upgrade to this updated package, which
  contains a backported patch to correct this issue. For the update to take
  effect, the named service must be restarted." );
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
	if(( res = isrpmvuln( pkg: "bind-dyndb-ldap", rpm: "bind-dyndb-ldap~1.1.0~0.9.b1.el6_3.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

