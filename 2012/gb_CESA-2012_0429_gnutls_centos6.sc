if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-March/018532.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881204" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:45:03 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-4128", "CVE-2012-1573" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2012:0429" );
	script_name( "CentOS Update for gnutls CESA-2012:0429 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "gnutls on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The GnuTLS library provides support for cryptographic algorithms and for
  protocols such as Transport Layer Security (TLS).

  A flaw was found in the way GnuTLS decrypted malformed TLS records. This
  could cause a TLS/SSL client or server to crash when processing a
  specially-crafted TLS record from a remote TLS/SSL connection peer.
  (CVE-2012-1573)

  A boundary error was found in the gnutls_session_get_data() function. A
  malicious TLS/SSL server could use this flaw to crash a TLS/SSL client or,
  possibly, execute arbitrary code as the client, if the client passed a
  fixed-sized buffer to gnutls_session_get_data() before checking the real
  size of the session data provided by the server. (CVE-2011-4128)

  Red Hat would like to thank Matthew Hall of Mu Dynamics for reporting
  CVE-2012-1573.

  Users of GnuTLS are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. For the update to take
  effect, all applications linked to the GnuTLS library must be restarted, or
  the system rebooted." );
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
	if(( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~2.8.5~4.el6_2.2", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-devel", rpm: "gnutls-devel~2.8.5~4.el6_2.2", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-guile", rpm: "gnutls-guile~2.8.5~4.el6_2.2", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-utils", rpm: "gnutls-utils~2.8.5~4.el6_2.2", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

