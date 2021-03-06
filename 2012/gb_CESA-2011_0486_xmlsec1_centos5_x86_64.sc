if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-May/017513.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881431" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:51:39 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-1425" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:0486" );
	script_name( "CentOS Update for xmlsec1 CESA-2011:0486 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xmlsec1'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "xmlsec1 on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "The XML Security Library is a C library based on libxml2 and OpenSSL that
  implements the XML Digital Signature and XML Encryption standards.

  A flaw was found in the way xmlsec1 handled XML files that contain an XSLT
  transformation specification. A specially-crafted XML file could cause
  xmlsec1 to create or overwrite an arbitrary file while performing the
  verification of a file's digital signature. (CVE-2011-1425)

  Red Hat would like to thank Nicolas Grgoire and Aleksey Sanin for
  reporting this issue.

  This update also fixes the following bug:

  * xmlsec1 previously used an incorrect search path when searching for
  crypto plug-in libraries, possibly trying to access such libraries using a
  relative path. (BZ#558480, BZ#700467)

  Users of xmlsec1 should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the update,
  all running applications that use the xmlsec1 library must be restarted for
  the update to take effect." );
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
	if(( res = isrpmvuln( pkg: "xmlsec1", rpm: "xmlsec1~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xmlsec1-devel", rpm: "xmlsec1-devel~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xmlsec1-gnutls", rpm: "xmlsec1-gnutls~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xmlsec1-gnutls-devel", rpm: "xmlsec1-gnutls-devel~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xmlsec1-nss", rpm: "xmlsec1-nss~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xmlsec1-nss-devel", rpm: "xmlsec1-nss-devel~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xmlsec1-openssl", rpm: "xmlsec1-openssl~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "xmlsec1-openssl-devel", rpm: "xmlsec1-openssl-devel~1.2.9~8.1.2", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

