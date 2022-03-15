if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879656" );
	script_version( "2021-08-20T14:00:58+0000" );
	script_cve_id( "CVE-2020-18032" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 14:00:58 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-03 06:15:00 +0000 (Sat, 03 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 03:20:03 +0000 (Thu, 27 May 2021)" );
	script_name( "Fedora: Security Advisory for graphviz (FEDORA-2021-ede783f2b6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-ede783f2b6" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QGY2IGARE6RZHTF2UEZEWLMQCDILFK6A" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'graphviz'
  package(s) announced via the FEDORA-2021-ede783f2b6 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A collection of tools for the manipulation and layout of graphs (as in nodes
and edges, not as in barcharts)." );
	script_tag( name: "affected", value: "'graphviz' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "graphviz", rpm: "graphviz~2.44.0~14.fc33.2", rls: "FC33" ) )){
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

