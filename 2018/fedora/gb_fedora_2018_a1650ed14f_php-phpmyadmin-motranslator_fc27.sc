if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874153" );
	script_version( "2021-06-14T02:00:24+0000" );
	script_tag( name: "last_modification", value: "2021-06-14 02:00:24 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-27 08:20:03 +0100 (Tue, 27 Feb 2018)" );
	script_cve_id( "CVE-2018-7260" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-06 15:07:00 +0000 (Tue, 06 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for php-phpmyadmin-motranslator FEDORA-2018-a1650ed14f" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-phpmyadmin-motranslator'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "php-phpmyadmin-motranslator on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-a1650ed14f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/E5UNWHTSG5WZZN3SGQMW6V4I2BQYXLOI" );
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
	if(( res = isrpmvuln( pkg: "php-phpmyadmin-motranslator", rpm: "php-phpmyadmin-motranslator~4.0~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

