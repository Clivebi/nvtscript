if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019654.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881692" );
	script_version( "2021-02-05T10:24:35+0000" );
	script_tag( name: "last_modification", value: "2021-02-05 10:24:35 +0000 (Fri, 05 Feb 2021)" );
	script_tag( name: "creation_date", value: "2013-03-19 09:38:25 +0530 (Tue, 19 Mar 2013)" );
	script_cve_id( "CVE-2012-1016", "CVE-2013-1415" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2013:0656" );
	script_name( "CentOS Update for krb5-devel CESA-2013:0656 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'krb5-devel'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "krb5-devel on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Kerberos is a network authentication system which allows clients and
  servers to authenticate to each other using symmetric encryption and a
  trusted third-party, the Key Distribution Center (KDC).

  When a client attempts to use PKINIT to obtain credentials from the KDC,
  the client can specify, using an issuer and serial number, which of the
  KDC's possibly-many certificates the client has in its possession, as a
  hint to the KDC that it should use the corresponding key to sign its
  response. If that specification was malformed, the KDC could attempt to
  dereference a NULL pointer and crash. (CVE-2013-1415)

  When a client attempts to use PKINIT to obtain credentials from the KDC,
  the client will typically format its request to conform to the
  specification published in RFC 4556. For interoperability reasons, clients
  and servers also provide support for an older, draft version of that
  specification. If a client formatted its request to conform to this older
  version of the specification, with a non-default key agreement option, it
  could cause the KDC to attempt to dereference a NULL pointer and crash.
  (CVE-2012-1016)

  All krb5 users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the krb5kdc daemon will be restarted automatically." );
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
	if(( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.10.3~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.10.3~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-pkinit-openssl", rpm: "krb5-pkinit-openssl~1.10.3~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.10.3~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-server-ldap", rpm: "krb5-server-ldap~1.10.3~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.10.3~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.10.3~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

