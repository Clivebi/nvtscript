if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874979" );
	script_version( "2021-06-11T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 11:00:20 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-22 06:58:16 +0200 (Wed, 22 Aug 2018)" );
	script_cve_id( "CVE-2018-1139", "CVE-2018-1140", "CVE-2018-10858", "CVE-2018-10918", "CVE-2018-10919", "CVE-2018-1050", "CVE-2018-1057", "CVE-2017-14746", "CVE-2017-15275" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-21 10:29:00 +0000 (Sun, 21 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for samba FEDORA-2018-8e4d871867" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "samba on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-8e4d871867" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7YJYQHQW2OGFNOT7P6SZ5G7A4EDHC2ND" );
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
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~4.7.9~0.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
