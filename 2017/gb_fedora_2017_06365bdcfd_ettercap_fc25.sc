if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872488" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-15 05:58:07 +0100 (Wed, 15 Mar 2017)" );
	script_cve_id( "CVE-2017-6430" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-26 13:35:00 +0000 (Wed, 26 Feb 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for ettercap FEDORA-2017-06365bdcfd" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ettercap'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ettercap on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-06365bdcfd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Q6NUJRIY4LV42YSZYHP34LOL73PN4ZO2" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC25" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC25"){
	if(( res = isrpmvuln( pkg: "ettercap", rpm: "ettercap~0.8.2~4.1.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

