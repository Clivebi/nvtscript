if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874742" );
	script_version( "2021-06-11T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 02:00:27 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-27 06:03:13 +0200 (Wed, 27 Jun 2018)" );
	script_cve_id( "CVE-2018-1000400" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for cri-o FEDORA-2018-0c9ce03fce" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cri-o'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is
present on the target host." );
	script_tag( name: "affected", value: "cri-o on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-0c9ce03fce" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7R6I6Z5ZOFKUQNN6ZYHOHQC457PC7DES" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
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
	if(( res = isrpmvuln( pkg: "cri-o", rpm: "cri-o~1.10.3~1.gite558bd5.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
