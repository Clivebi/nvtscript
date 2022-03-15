if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-July/016021.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880868" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2009:1138" );
	script_cve_id( "CVE-2009-2185" );
	script_name( "CentOS Update for openswan CESA-2009:1138 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openswan'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "openswan on CentOS 5" );
	script_tag( name: "insight", value: "Openswan is a free implementation of Internet Protocol Security (IPsec)
  and Internet Key Exchange (IKE). IPsec uses strong cryptography to provide
  both authentication and encryption services. These services allow you to
  build secure tunnels through untrusted networks. Everything passing through
  the untrusted network is encrypted by the IPsec gateway machine, and
  decrypted by the gateway at the other end of the tunnel. The resulting
  tunnel is a virtual private network (VPN).

  Multiple insufficient input validation flaws were found in the way
  Openswan's pluto IKE daemon processed some fields of X.509 certificates. A
  remote attacker could provide a specially-crafted X.509 certificate that
  would crash the pluto daemon. (CVE-2009-2185)

  All users of openswan are advised to upgrade to these updated packages,
  which contain a backported patch to correct these issues. After installing
  this update, the ipsec service will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "openswan", rpm: "openswan~2.6.14~1.el5_3.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openswan-doc", rpm: "openswan-doc~2.6.14~1.el5_3.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
