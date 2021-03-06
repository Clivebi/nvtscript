if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881895" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-12 09:28:40 +0530 (Wed, 12 Mar 2014)" );
	script_cve_id( "CVE-2009-5138", "CVE-2014-0092" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_name( "CentOS Update for gnutls CESA-2014:0247 centos5" );
	script_tag( name: "affected", value: "gnutls on CentOS 5" );
	script_tag( name: "insight", value: "The GnuTLS library provides support for cryptographic algorithms and for
protocols such as Transport Layer Security (TLS).

It was discovered that GnuTLS did not correctly handle certain errors that
could occur during the verification of an X.509 certificate, causing it to
incorrectly report a successful verification. An attacker could use this
flaw to create a specially crafted certificate that could be accepted by
GnuTLS as valid for a site chosen by the attacker. (CVE-2014-0092)

A flaw was found in the way GnuTLS handled version 1 X.509 certificates.
An attacker able to obtain a version 1 certificate from a trusted
certificate authority could use this flaw to issue certificates for other
sites that would be accepted by GnuTLS as valid. (CVE-2009-5138)

The CVE-2014-0092 issue was discovered by Nikos Mavrogiannopoulos of the
Red Hat Security Technologies Team.

Users of GnuTLS are advised to upgrade to these updated packages, which
correct these issues. For the update to take effect, all applications
linked to the GnuTLS library must be restarted." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0247" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-March/020183.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gnutls'
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
	if(( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~1.4.1~14.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-devel", rpm: "gnutls-devel~1.4.1~14.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gnutls-utils", rpm: "gnutls-utils~1.4.1~14.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

