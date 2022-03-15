if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879564" );
	script_version( "2021-08-20T14:00:58+0000" );
	script_cve_id( "CVE-2021-2146", "CVE-2021-2164", "CVE-2021-2166", "CVE-2021-2169", "CVE-2021-2170", "CVE-2021-2171", "CVE-2021-2172", "CVE-2021-2174", "CVE-2021-2178", "CVE-2021-2179", "CVE-2021-2180", "CVE-2021-2193", "CVE-2021-2194", "CVE-2021-2196" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:00:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-13 18:15:00 +0000 (Thu, 13 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-13 03:19:32 +0000 (Thu, 13 May 2021)" );
	script_name( "Fedora: Security Advisory for community-mysql (FEDORA-2021-01189f6361)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-01189f6361" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/AKV7TRUEQW6EV45RSZVVFLVQMNHVHBCJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'community-mysql'
  package(s) announced via the FEDORA-2021-01189f6361 advisory." );
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
	if(!isnull( res = isrpmvuln( pkg: "community-mysql", rpm: "community-mysql~8.0.24~1.fc34", rls: "FC34" ) )){
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

