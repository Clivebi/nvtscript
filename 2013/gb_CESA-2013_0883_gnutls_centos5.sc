if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881738" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-05-31 09:51:13 +0530 (Fri, 31 May 2013)" );
	script_cve_id( "CVE-2013-2116", "CVE-2013-1619" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "CentOS Update for gnutls CESA-2013:0883 centos5" );
	script_xref( name: "CESA", value: "2013:0883" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-May/019766.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "gnutls on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The GnuTLS library provides support for cryptographic algorithms and for
  protocols such as Transport Layer Security (TLS).

  It was discovered that the fix for the CVE-2013-1619 issue released via
  RHSA-2013:0588 introduced a regression in the way GnuTLS decrypted TLS/SSL
  encrypted records when CBC-mode cipher suites were used. A remote attacker
  could possibly use this flaw to crash a server or client application that
  uses GnuTLS. (CVE-2013-2116)

  Users of GnuTLS are advised to upgrade to these updated packages, which
  correct this issue. For the update to take effect, all applications linked
  to the GnuTLS library must be restarted." );
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
	if(( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~1.4.1~10.el5_9.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-devel", rpm: "gnutls-devel~1.4.1~10.el5_9.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-utils", rpm: "gnutls-utils~1.4.1~10.el5_9.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

