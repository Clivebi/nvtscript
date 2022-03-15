if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871563" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-03-02 06:16:51 +0100 (Wed, 02 Mar 2016)" );
	script_cve_id( "CVE-2015-3197", "CVE-2016-0797", "CVE-2016-0800" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for openssl RHSA-2016:0302-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements
  the Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1) protocols,
  as well as a full-strength, general purpose cryptography library.

  A padding oracle flaw was found in the Secure Sockets Layer version 2.0
  (SSLv2) protocol. An attacker can potentially use this flaw to decrypt
  RSA-encrypted cipher text from a connection using a newer SSL/TLS protocol
  version, allowing them to decrypt such connections. This cross-protocol
  attack is publicly referred to as DROWN. (CVE-2016-0800)

  Note: This issue was addressed by disabling the SSLv2 protocol by default
  when using the 'SSLv23' connection methods, and removing support for weak
  SSLv2 cipher suites. It is possible to re-enable the SSLv2 protocol in the
  'SSLv23' connection methods by default by setting the OPENSSL_ENABLE_SSL2
  environment variable before starting an application that needs to have
  SSLv2 enabled. For more information, refer to the knowledge base article
  linked to in the References section.

  A flaw was found in the way malicious SSLv2 clients could negotiate SSLv2
  ciphers that have been disabled on the server. This could result in weak
  SSLv2 ciphers being used for SSLv2 connections, making them vulnerable to
  man-in-the-middle attacks. (CVE-2015-3197)

  An integer overflow flaw, leading to a NULL pointer dereference or a
  heap-based memory corruption, was found in the way some BIGNUM functions of
  OpenSSL were implemented. Applications that use these functions with large
  untrusted input could crash or, potentially, execute arbitrary code.
  (CVE-2016-0797)

  Red Hat would like to thank the OpenSSL project for reporting these issues.
  Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as the original
  reporters of CVE-2016-0800 and CVE-2015-3197  and Guido Vranken as the
  original reporter of CVE-2016-0797.

  All openssl users are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. For the update to take
  effect, all services linked to the OpenSSL library must be restarted, or
  the system rebooted." );
	script_tag( name: "affected", value: "openssl on Red Hat Enterprise Linux (v. 5 server)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:0302-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-March/msg00003.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_5"){
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8e~39.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~0.9.8e~39.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~0.9.8e~39.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-perl", rpm: "openssl-perl~0.9.8e~39.el5_11", rls: "RHENT_5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

