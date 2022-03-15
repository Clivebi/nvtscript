if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817766" );
	script_version( "2021-09-03T10:01:28+0000" );
	script_cve_id( "CVE-2021-2339", "CVE-2021-2340", "CVE-2021-2342", "CVE-2021-2352", "CVE-2021-2354", "CVE-2021-2356", "CVE-2021-2357", "CVE-2021-2367", "CVE-2021-2370", "CVE-2021-2372", "CVE-2021-2374", "CVE-2021-2383", "CVE-2021-2384", "CVE-2021-2385" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-03 10:01:28 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-23 13:42:00 +0000 (Fri, 23 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-08-26 03:11:02 +0000 (Thu, 26 Aug 2021)" );
	script_name( "Fedora: Security Advisory for community-mysql (FEDORA-2021-df40c41094)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-df40c41094" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OPJAGVMRKODR4QIXQSVEM4BLRZUM7P3R" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2021-df40c41094 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MySQL is a multi-user, multi-threaded SQL database server. MySQL is a
client/server implementation consisting of a server daemon (mysqld)
and many different client programs and libraries. The base package
contains the standard MySQL client programs and generic MySQL files." );
	script_tag( name: "affected", value: "'community-mysql' package(s) on Fedora 34." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "community-mysql", rpm: "community-mysql~8.0.26~1.fc34", rls: "FC34" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

