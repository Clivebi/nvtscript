if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881964" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-07-28 16:29:06 +0530 (Mon, 28 Jul 2014)" );
	script_cve_id( "CVE-2014-1544" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for nspr CESA-2014:0916 centos5" );
	script_tag( name: "affected", value: "nspr on CentOS 5" );
	script_tag( name: "insight", value: "Network Security Services (NSS) is a set of libraries designed
to support the cross-platform development of security-enabled client and server
applications. Netscape Portable Runtime (NSPR) provides platform
independence for non-GUI operating system facilities.

A race condition was found in the way NSS verified certain certificates.
A remote attacker could use this flaw to crash an application using NSS or,
possibly, execute arbitrary code with the privileges of the user running
that application. (CVE-2014-1544)

Red Hat would like to thank the Mozilla project for reporting
CVE-2014-1544. Upstream acknowledges Tyson Smith and Jesse Schwartzentruber
as the original reporters.

Users of NSS and NSPR are advised to upgrade to these updated packages,
which correct this issue. After installing this update, applications using
NSS or NSPR must be restarted for this update to take effect." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:0916" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-July/020427.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nspr'
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
	if(( res = isrpmvuln( pkg: "nspr", rpm: "nspr~4.10.6~1.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "nspr-devel", rpm: "nspr-devel~4.10.6~1.el5_10", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

