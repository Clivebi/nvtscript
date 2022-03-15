if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882597" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-20 05:37:26 +0100 (Sun, 20 Nov 2016)" );
	script_cve_id( "CVE-2016-2834", "CVE-2016-5285", "CVE-2016-8635" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for nss CESA-2016:2779 centos6" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set
of libraries designed to support the cross-platform development of security-enabled
client and server applications.

The nss-util packages provide utilities for use with the Network Security
Services (NSS) libraries.

The following packages have been upgraded to a newer upstream version: nss
(3.12.3), nss-util (3.12.3).

Security Fix(es):

  * Multiple buffer handling flaws were found in the way NSS handled
cryptographic data from the network. A remote attacker could use these
flaws to crash an application using NSS or, possibly, execute arbitrary
code with the permission of the user running the application.
(CVE-2016-2834)

  * A NULL pointer dereference flaw was found in the way NSS handled invalid
Diffie-Hellman keys. A remote client could use this flaw to crash a TLS/SSL
server using NSS. (CVE-2016-5285)

  * It was found that Diffie Hellman Client key exchange handling in NSS was
vulnerable to small subgroup confinement attack. An attacker could use this
flaw to recover private keys by confining the client DH key to small
subgroup of the desired group. (CVE-2016-8635)

Red Hat would like to thank the Mozilla project for reporting
CVE-2016-2834. The CVE-2016-8635 issue was discovered by Hubert Kario (Red
Hat). Upstream acknowledges Tyson Smith and Jed Davis as the original
reporter of CVE-2016-2834." );
	script_tag( name: "affected", value: "nss on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:2779" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-November/022152.html" );
	script_tag( name: "summary", value: "Check for the Version of nss" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
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
	if(( res = isrpmvuln( pkg: "nss", rpm: "nss~3.21.3~2.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.21.3~2.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-pkcs11-devel", rpm: "nss-pkcs11-devel~3.21.3~2.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-sysinit", rpm: "nss-sysinit~3.21.3~2.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.21.3~2.el6_8", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

