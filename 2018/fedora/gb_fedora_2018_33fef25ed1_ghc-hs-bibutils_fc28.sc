if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875023" );
	script_version( "2021-06-10T11:00:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-10 11:00:22 +0000 (Thu, 10 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-01 07:40:25 +0200 (Sat, 01 Sep 2018)" );
	script_cve_id( "CVE-2018-10773", "CVE-2018-10774", "CVE-2018-10775" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-13 12:07:00 +0000 (Wed, 13 Jun 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for ghc-hs-bibutils FEDORA-2018-33fef25ed1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghc-hs-bibutils'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "ghc-hs-bibutils on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-33fef25ed1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GASRULEM33GJ5SL76SYQMPLLETNL34RN" );
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
	if(( res = isrpmvuln( pkg: "ghc-hs-bibutils", rpm: "ghc-hs-bibutils~6.6.0.0~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

