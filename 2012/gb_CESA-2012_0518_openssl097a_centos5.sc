if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-April/018592.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881108" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:09:21 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-2110" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2012:0518" );
	script_name( "CentOS Update for openssl097a CESA-2012:0518 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl097a'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "openssl097a on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL v2/v3)
  and Transport Layer Security (TLS v1) protocols, as well as a
  full-strength, general purpose cryptography library.

  Multiple numeric conversion errors, leading to a buffer overflow, were
  found in the way OpenSSL parsed ASN.1 (Abstract Syntax Notation One) data
  from BIO (OpenSSL's I/O abstraction) inputs. Specially-crafted DER
  (Distinguished Encoding Rules) encoded data read from a file or other BIO
  input could cause an application using the OpenSSL library to crash or,
  potentially, execute arbitrary code. (CVE-2012-2110)

  All OpenSSL users should upgrade to these updated packages, which contain
  a backported patch to resolve this issue. For the update to take effect,
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "openssl097a", rpm: "openssl097a~0.9.7a~11.el5_8.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8e~22.el5_8.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~0.9.8e~22.el5_8.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~0.9.8e~22.el5_8.3", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

