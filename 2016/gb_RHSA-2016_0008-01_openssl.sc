if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871536" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-01-08 06:30:14 +0100 (Fri, 08 Jan 2016)" );
	script_cve_id( "CVE-2015-7575" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for openssl RHSA-2016:0008-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "OpenSSL is a toolkit that implements the
Secure Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1) protocols,
as well as a full-strength, general purpose cryptography library.

A flaw was found in the way TLS 1.2 could use the MD5 hash function for
signing ServerKeyExchange and Client Authentication packets during a TLS
handshake. A man-in-the-middle attacker able to force a TLS connection to
use the MD5 hash function could use this flaw to conduct collision attacks
to impersonate a TLS server or an authenticated TLS client. (CVE-2015-7575)

All openssl users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to take
effect, all services linked to the OpenSSL library must be restarted, or
the system rebooted." );
	script_tag( name: "affected", value: "openssl on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:0008-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-January/msg00006.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_(7|6)" );
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
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1e~51.el7_2.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.1e~51.el7_2.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.1e~51.el7_2.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-libs", rpm: "openssl-libs~1.0.1e~51.el7_2.2", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1e~42.el6_7.2", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.1e~42.el6_7.2", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~1.0.1e~42.el6_7.2", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

