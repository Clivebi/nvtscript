if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878778" );
	script_version( "2021-08-23T06:00:57+0000" );
	script_cve_id( "CVE-2020-15113", "CVE-2020-15112", "CVE-2020-15114", "CVE-2020-15115", "CVE-2020-15136", "CVE-2020-15106" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-23 06:00:57 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 03:15:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "creation_date", value: "2021-01-11 10:58:55 +0000 (Mon, 11 Jan 2021)" );
	script_name( "Fedora: Security Advisory for etcd (FEDORA-2020-cd43b84c16)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-cd43b84c16" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/L6B6R43Y7M3DCHWK3L3UVGE2K6WWECMP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'etcd'
  package(s) announced via the FEDORA-2020-cd43b84c16 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Distributed reliable key-value store for the most critical data of a distributed
system." );
	script_tag( name: "affected", value: "'etcd' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "etcd", rpm: "etcd~3.4.13~1.fc32", rls: "FC32" ) )){
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
