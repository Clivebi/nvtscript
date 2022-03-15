if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873204" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-04 12:47:16 +0530 (Fri, 04 Aug 2017)" );
	script_cve_id( "CVE-2017-11671" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-12 01:29:00 +0000 (Thu, 12 Apr 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for gcc FEDORA-2017-32a4a94c72" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gcc'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "gcc on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-32a4a94c72" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VY6TDQVYXVERFXCHG3SPGKFLXSLCYW2L" );
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
	if(( res = isrpmvuln( pkg: "gcc", rpm: "gcc~6.4.1~1.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

