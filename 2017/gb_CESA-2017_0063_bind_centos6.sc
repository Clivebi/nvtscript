if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882634" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-18 05:46:13 +0100 (Wed, 18 Jan 2017)" );
	script_cve_id( "CVE-2016-9147" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-27 10:29:00 +0000 (Thu, 27 Sep 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for bind CESA-2017:0063 centos6" );
	script_tag( name: "summary", value: "Check the version of bind" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Berkeley Internet Name Domain (BIND)
is an implementation of the Domain Name System (DNS) protocols. BIND includes
a DNS server (named)  a resolver library (routines for applications to use
when interfacing with DNS)  and tools for verifying that the DNS server is
operating correctly.

Security Fix(es):

  * A denial of service flaw was found in the way BIND handled a query
response containing inconsistent DNSSEC information. A remote attacker
could use this flaw to make named exit unexpectedly with an assertion
failure via a specially crafted DNS response. (CVE-2016-9147)

Red Hat would like to thank ISC for reporting this issue." );
	script_tag( name: "affected", value: "bind on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:0063" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-January/022214.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "bind", rpm: "bind~9.8.2~0.47.rc1.el6_8.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-chroot", rpm: "bind-chroot~9.8.2~0.47.rc1.el6_8.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-devel", rpm: "bind-devel~9.8.2~0.47.rc1.el6_8.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-libs", rpm: "bind-libs~9.8.2~0.47.rc1.el6_8.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-sdb", rpm: "bind-sdb~9.8.2~0.47.rc1.el6_8.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bind-utils", rpm: "bind-utils~9.8.2~0.47.rc1.el6_8.4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

