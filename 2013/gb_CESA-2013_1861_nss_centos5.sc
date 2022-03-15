if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881853" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-12-23 12:47:16 +0530 (Mon, 23 Dec 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for nss CESA-2013:1861 centos5" );
	script_tag( name: "affected", value: "nss on CentOS 5" );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set of libraries designed to support
the cross-platform development of security-enabled client and server
applications.

It was found that a subordinate Certificate Authority (CA) mis-issued an
intermediate certificate, which could be used to conduct man-in-the-middle
attacks. This update renders that particular intermediate certificate as
untrusted. (BZ#1038894)

Note: This fix only applies to applications using the NSS Builtin Object
Token. It does not render the certificates untrusted for applications that
use the NSS library, but do not use the NSS Builtin Object Token.

All NSS users should upgrade to these updated packages, which correct this
issue. After installing the update, applications using NSS must be
restarted for the changes to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:1861" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-December/020086.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "nss", rpm: "nss~3.15.3~4.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.15.3~4.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-pkcs11-devel", rpm: "nss-pkcs11-devel~3.15.3~4.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.15.3~4.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

