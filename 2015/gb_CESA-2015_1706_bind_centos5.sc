if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882273" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-09-04 08:14:42 +0200 (Fri, 04 Sep 2015)" );
	script_cve_id( "CVE-2015-5722" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for bind CESA-2015:1706 centos5" );
	script_tag( name: "summary", value: "Check the version of bind" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Berkeley Internet Name Domain (BIND) is an implementation of the Domain
Name System (DNS) protocols. BIND includes a DNS server (named)  a resolver
library (routines for applications to use when interfacing with DNS)  and
tools for verifying that the DNS server is operating correctly.

A denial of service flaw was found in the way BIND parsed certain malformed
DNSSEC keys. A remote attacker could use this flaw to send a specially
crafted DNS query (for example, a query requiring a response from a zone
containing a deliberately malformed key) that would cause named functioning
as a validating resolver to crash. (CVE-2015-5722)

Red Hat would like to thank ISC for reporting this issue. Upstream
acknowledges Hanno Bock as the original reporter.

All bind users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, the BIND daemon (named) will be restarted automatically." );
	script_tag( name: "affected", value: "bind on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1706" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-September/021370.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-chroot", rpm: "bind-chroot~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-libbind-devel", rpm: "bind-libbind-devel~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-sdb", rpm: "bind-sdb~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "caching-nameserver", rpm: "caching-nameserver~9.3.6~25.P1.el5_11.4", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
