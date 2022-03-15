if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876682" );
	script_version( "2021-09-01T13:01:35+0000" );
	script_cve_id( "CVE-2018-20349" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 13:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-14 03:15:00 +0000 (Wed, 14 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-14 02:35:06 +0000 (Wed, 14 Aug 2019)" );
	script_name( "Fedora Update for igraph FEDORA-2019-5d52865475" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-5d52865475" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OWCGXEINKJM3JQUPVCSN4RBTRKWBTYI7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'igraph'
  package(s) announced via the FEDORA-2019-5d52865475 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "igraph wants to be an efficient platform for
1) complex network analysis and
2) developing and implementing graph algorithms.
It provides flexible and efficient data structures for graphs and related
tasks. It also provides implementation to many classic and new graph
algorithms like: maximum flows, graph isomorphism, scale-free
networks, community structure finding, etc." );
	script_tag( name: "affected", value: "'igraph' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "igraph", rpm: "igraph~0.7.1~12.fc29", rls: "FC29" ) )){
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

