if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871692" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-11-04 05:41:57 +0100 (Fri, 04 Nov 2016)" );
	script_cve_id( "CVE-2016-3099" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for mod_nss RHSA-2016:2602-02" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mod_nss'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The mod_nss module provides strong
cryptography for the Apache HTTP Server via the Secure Sockets Layer (SSL)
and Transport Layer Security (TLS) protocols, using the Network Security
Services (NSS) security library.

The following packages have been upgraded to a newer upstream version:
mod_nss (1.0.14). (BZ#1299063)

Security Fix(es):

  * A flaw was found in the way mod_nss parsed certain OpenSSL-style cipher
strings. As a result, mod_nss could potentially use ciphers that were not
intended to be enabled. (CVE-2016-3099)

This issue was discovered by Rob Crittenden (Red Hat).

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section." );
	script_tag( name: "affected", value: "mod_nss on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2602-02" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-November/msg00038.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "mod_nss", rpm: "mod_nss~1.0.14~7.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_nss-debuginfo", rpm: "mod_nss-debuginfo~1.0.14~7.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

