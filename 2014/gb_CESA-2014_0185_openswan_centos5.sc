if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881886" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-02-20 15:10:40 +0530 (Thu, 20 Feb 2014)" );
	script_cve_id( "CVE-2013-6466" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "CentOS Update for openswan CESA-2014:0185 centos5" );
	script_tag( name: "affected", value: "openswan on CentOS 5" );
	script_tag( name: "insight", value: "Openswan is a free implementation of Internet Protocol Security (IPsec) and
Internet Key Exchange (IKE). IPsec uses strong cryptography to provide both
authentication and encryption services. These services allow you to build
secure tunnels through untrusted networks.

A NULL pointer dereference flaw was discovered in the way Openswan's IKE
daemon processed IKEv2 payloads. A remote attacker could send specially
crafted IKEv2 payloads that, when processed, would lead to a denial of
service (daemon crash), possibly causing existing VPN connections to be
dropped. (CVE-2013-6466)

All openswan users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0185" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-February/020162.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openswan'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
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
	if(( res = isrpmvuln( pkg: "openswan", rpm: "openswan~2.6.32~7.3.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openswan-doc", rpm: "openswan-doc~2.6.32~7.3.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

