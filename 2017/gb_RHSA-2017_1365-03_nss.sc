if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871825" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-30 15:54:47 +0200 (Tue, 30 May 2017)" );
	script_cve_id( "CVE-2017-7502" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for nss RHSA-2017:1365-03" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set of
  libraries designed to support the cross-platform development of security-enabled
  client and server applications.

Security Fix(es):

  * A null pointer dereference flaw was found in the way NSS handled empty
SSLv2 messages. An attacker could use this flaw to crash a server
application compiled against the NSS library. (CVE-2017-7502)

Bug Fix(es):

  * The Network Security Services (NSS) code and Certificate Authority (CA)
list have been updated to meet the recommendations as published with the
latest Mozilla Firefox Extended Support Release (ESR). The updated CA list
improves compatibility with the certificates that are used in the Internet
Public Key Infrastructure (PKI). To avoid certificate validation refusals,
Red Hat recommends installing the updated CA list on June 12, 2017.
(BZ#1451421)" );
	script_tag( name: "affected", value: "nss on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:1365-03" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-May/msg00045.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "nss", rpm: "nss~3.28.4~1.2.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-debuginfo", rpm: "nss-debuginfo~3.28.4~1.2.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.28.4~1.2.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-sysinit", rpm: "nss-sysinit~3.28.4~1.2.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.28.4~1.2.el7_3", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

