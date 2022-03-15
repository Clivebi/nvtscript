if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874663" );
	script_version( "2021-06-11T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 11:00:20 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-06-09 06:01:39 +0200 (Sat, 09 Jun 2018)" );
	script_cve_id( "CVE-2017-13685", "CVE-2017-15286", "CVE-2018-8740" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-10-27 14:18:00 +0000 (Fri, 27 Oct 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for sqlite FEDORA-2018-8d8f0e1643" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sqlite'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "sqlite on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-8d8f0e1643" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5NZZAIFXIBPTX4ETB4R6PJE66SVCQFLC" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "sqlite", rpm: "sqlite~3.20.1~3.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

