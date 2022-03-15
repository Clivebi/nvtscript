if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875312" );
	script_version( "2021-06-08T11:00:18+0000" );
	script_cve_id( "CVE-2018-16471" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-08 11:00:18 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-13 21:29:00 +0000 (Thu, 13 Jun 2019)" );
	script_tag( name: "creation_date", value: "2018-12-04 08:24:07 +0100 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for rubygem-rack FEDORA-2018-5743ef02a1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	script_xref( name: "FEDORA", value: "2018-5743ef02a1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MMYLVM7OEZW6L7K3OIMNEXR3UJ3PDWAU" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-rack'
  package(s) announced via the FEDORA-2018-5743ef02a1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "rubygem-rack on Fedora 27." );
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
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "rubygem-rack", rpm: "rubygem-rack~2.0.3~4.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

