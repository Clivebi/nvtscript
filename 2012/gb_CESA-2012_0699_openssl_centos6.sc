if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-May/018659.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881151" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:23:36 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-2333", "CVE-2012-0884" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:0699" );
	script_name( "CentOS Update for openssl CESA-2012:0699 centos6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_tag( name: "affected", value: "openssl on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  An integer underflow flaw, leading to a buffer over-read, was found in the
  way OpenSSL handled DTLS (Datagram Transport Layer Security) application
  data record lengths when using a block cipher in CBC (cipher-block
  chaining) mode. A malicious DTLS client or server could use this flaw to
  crash its DTLS connection peer. (CVE-2012-2333)

  Red Hat would like to thank the OpenSSL project for reporting this issue.
  Upstream acknowledges Codenomicon as the original reporter.

  On Red Hat Enterprise Linux 6, this update also fixes an uninitialized
  variable use bug, introduced by the fix for CVE-2012-0884 (released via
  RHSA-2012:0426). This bug could possibly cause an attempt to create an
  encrypted message in the CMS (Cryptographic Message Syntax) format to fail.

  All OpenSSL users should upgrade to these updated packages, which contain a
  backported patch to resolve these issues. For the update to take effect,
  all services linked to the OpenSSL library must be restarted, or the system
  rebooted." );
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
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.0~20.el6_2.5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.0~20.el6_2.5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~1.0.0~20.el6_2.5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-static", rpm: "openssl-static~1.0.0~20.el6_2.5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

