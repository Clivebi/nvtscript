if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875291" );
	script_version( "2021-06-09T11:00:19+0000" );
	script_cve_id( "CVE-2018-16646", "CVE-2018-19058", "CVE-2018-19059", "CVE-2018-19060", "CVE-2018-13988", "CVE-2017-18267" );
	script_bugtraq_id( 106054 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-09 11:00:19 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-23 12:15:00 +0000 (Thu, 23 Jul 2020)" );
	script_tag( name: "creation_date", value: "2018-12-04 12:40:45 +0530 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for poppler FEDORA-2018-54ed26a423" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-54ed26a423" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KQ5WSZTPZ3WOIMO2P3MZYR6NKNLSLQBM" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the FEDORA-2018-54ed26a423 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "poppler on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.62.0~10.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
