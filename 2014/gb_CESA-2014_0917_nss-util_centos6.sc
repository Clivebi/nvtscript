if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881967" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-28 16:30:14 +0530 (Mon, 28 Jul 2014)" );
	script_cve_id( "CVE-2013-1740", "CVE-2014-1490", "CVE-2014-1491", "CVE-2014-1492", "CVE-2014-1544", "CVE-2014-1545" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for nss-util CESA-2014:0917 centos6" );
	script_tag( name: "affected", value: "nss-util on CentOS 6" );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set of libraries designed
to support the cross-platform development of security-enabled client and server
applications. Netscape Portable Runtime (NSPR) provides platform
independence for non-GUI operating system facilities.

A race condition was found in the way NSS verified certain certificates.
A remote attacker could use this flaw to crash an application using NSS or,
possibly, execute arbitrary code with the privileges of the user running
that application. (CVE-2014-1544)

A flaw was found in the way TLS False Start was implemented in NSS.
An attacker could use this flaw to potentially return unencrypted
information from the server. (CVE-2013-1740)

A race condition was found in the way NSS implemented session ticket
handling as specified by RFC 5077. An attacker could use this flaw to crash
an application using NSS or, in rare cases, execute arbitrary code with the
privileges of the user running that application. (CVE-2014-1490)

It was found that NSS accepted weak Diffie-Hellman Key exchange (DHKE)
parameters. This could possibly lead to weak encryption being used in
communication between the client and the server. (CVE-2014-1491)

An out-of-bounds write flaw was found in NSPR. A remote attacker could
potentially use this flaw to crash an application using NSPR or, possibly,
execute arbitrary code with the privileges of the user running that
application. This NSPR flaw was not exposed to web content in any shipped
version of Firefox. (CVE-2014-1545)

It was found that the implementation of Internationalizing Domain Names in
Applications (IDNA) hostname matching in NSS did not follow the RFC 6125
recommendations. This could lead to certain invalid certificates with
international characters to be accepted as valid. (CVE-2014-1492)

Red Hat would like to thank the Mozilla project for reporting the
CVE-2014-1544, CVE-2014-1490, CVE-2014-1491, and CVE-2014-1545 issues.
Upstream acknowledges Tyson Smith and Jesse Schwartzentruber as the
original reporters of CVE-2014-1544, Brian Smith as the original reporter
of CVE-2014-1490, Antoine Delignat-Lavaud and Karthikeyan Bhargavan as the
original reporters of CVE-2014-1491, and Abhishek Arya as the original
reporter of CVE-2014-1545.

In addition, the nss package has been upgraded to upstream version 3.16.1,
and the nspr package has been upgraded to upstream version 4.10.6. These
updated packages provide a number of bug fixes and enhancements over the
previous versions. (BZ#1112136, BZ#1112135)

Users of NSS and NSPR are advised to upgrade to these updated packages,
which correct these issues and add these enhancements. After installing
this update, applications using NSS or NSPR must be restarted for this
update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0917" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-July/020436.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nss-util'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "nss-util", rpm: "nss-util~3.16.1~1.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nss-util-devel", rpm: "nss-util-devel~3.16.1~1.el6_5", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

