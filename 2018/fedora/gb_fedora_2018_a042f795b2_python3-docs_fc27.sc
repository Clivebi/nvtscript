if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874351" );
	script_version( "2021-06-10T11:00:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-10 11:00:22 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-10 08:56:09 +0200 (Tue, 10 Apr 2018)" );
	script_cve_id( "CVE-2018-1060", "CVE-2018-1061" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-15 20:15:00 +0000 (Wed, 15 Jan 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for python3-docs FEDORA-2018-a042f795b2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python3-docs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "python3-docs on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-a042f795b2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4NIP7KL6OITRSKD2LO4VQCLV2SRW7SOM" );
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
	if(( res = isrpmvuln( pkg: "python3-docs", rpm: "python3-docs~3.6.5~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
