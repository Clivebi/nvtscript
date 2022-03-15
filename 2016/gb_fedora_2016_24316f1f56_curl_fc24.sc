if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808776" );
	script_version( "2020-05-14T09:33:44+0000" );
	script_tag( name: "last_modification", value: "2020-05-14 09:33:44 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2016-08-06 05:48:19 +0200 (Sat, 06 Aug 2016)" );
	script_cve_id( "CVE-2016-5420", "CVE-2016-5419", "CVE-2016-5421" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for curl FEDORA-2016-24316f1f56" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "curl on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-24316f1f56" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GLPXQQKURBQFM4XM6645VRPTOE2AWG33" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "curl", rpm: "curl~7.47.1~6.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
