if(description){
	script_tag( name: "affected", value: "gnutls on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The GnuTLS library provides support for cryptographic algorithms and for
  protocols such as Transport Layer Security (TLS).

  It was discovered that GnuTLS leaked timing information when decrypting
  TLS/SSL protocol encrypted records when CBC-mode cipher suites were used.
  A remote attacker could possibly use this flaw to retrieve plain text from
  the encrypted packets by using a TLS/SSL server as a padding oracle.
  (CVE-2013-1619)

  Users of GnuTLS are advised to upgrade to these updated packages, which
  contain a backported patch to correct this issue. For the update to take
  effect, all applications linked to the GnuTLS library must be restarted,
  or the system rebooted." );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-March/019620.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881676" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-03-12 10:02:22 +0530 (Tue, 12 Mar 2013)" );
	script_cve_id( "CVE-2013-1619" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:0588" );
	script_name( "CentOS Update for gnutls CESA-2013:0588 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~2.8.5~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-devel", rpm: "gnutls-devel~2.8.5~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-guile", rpm: "gnutls-guile~2.8.5~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-utils", rpm: "gnutls-utils~2.8.5~10.el6_4.1", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

