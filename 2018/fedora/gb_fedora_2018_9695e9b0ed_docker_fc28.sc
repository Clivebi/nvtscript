if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874812" );
	script_version( "2021-06-09T11:00:19+0000" );
	script_tag( name: "last_modification", value: "2021-06-09 11:00:19 +0000 (Wed, 09 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-15 06:04:35 +0200 (Sun, 15 Jul 2018)" );
	script_cve_id( "CVE-2018-10892" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-31 15:49:00 +0000 (Mon, 31 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for docker FEDORA-2018-9695e9b0ed" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'docker'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "docker on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-9695e9b0ed" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZROWSFFIHGDTF4YUUQMDDKXOWPTGADSF" );
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
	if(( res = isrpmvuln( pkg: "docker", rpm: "docker~1.13.1~60.git9cb56fd.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
