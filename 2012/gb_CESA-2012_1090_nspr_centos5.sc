if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2012-July/018743.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881211" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 16:46:20 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2012-0441" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2012:1090" );
	script_name( "CentOS Update for nspr CESA-2012:1090 centos5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nspr'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "nspr on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set of libraries designed to support
  the cross-platform development of security-enabled client and server
  applications. Netscape Portable Runtime (NSPR) provides platform
  independence for non-GUI operating system facilities.

  A flaw was found in the way the ASN.1 (Abstract Syntax Notation One)
  decoder in NSS handled zero length items. This flaw could cause the decoder
  to incorrectly skip or replace certain items with a default value, or could
  cause an application to crash if, for example, it received a
  specially-crafted OCSP (Online Certificate Status Protocol) response.
  (CVE-2012-0441)

  It was found that a Certificate Authority (CA) issued a subordinate CA
  certificate to its customer, that could be used to issue certificates for
  any name. This update renders the subordinate CA certificate as untrusted.
  (BZ#798533)

  Note: The BZ#798533 fix only applies to applications using the NSS Builtin
  Object Token. It does not render the certificates untrusted for
  applications that use the NSS library, but do not use the NSS Builtin
  Object Token.

  In addition, the nspr package has been upgraded to upstream version 4.9.1,
  and the nss package has been upgraded to upstream version 3.13.5. These
  updates provide a number of bug fixes and enhancements over the previous
  versions. (BZ#834220, BZ#834219)

  All NSS and NSPR users should upgrade to these updated packages, which
  correct these issues and add these enhancements. After installing the
  update, applications using NSS and NSPR must be restarted for the changes
  to take effect." );
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
	if(( res = isrpmvuln( pkg: "nspr", rpm: "nspr~4.9.1~4.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nspr-devel", rpm: "nspr-devel~4.9.1~4.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss", rpm: "nss~3.13.5~4.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.13.5~4.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-pkcs11-devel", rpm: "nss-pkcs11-devel~3.13.5~4.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.13.5~4.el5_8", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

