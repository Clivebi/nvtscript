if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872657" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-10 07:02:34 +0200 (Wed, 10 May 2017)" );
	script_cve_id( "CVE-2017-5662" );
	script_tag( name: "cvss_base", value: "7.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for batik FEDORA-2017-aff3dd3101" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'batik'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "batik on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-aff3dd3101" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UVNDHXPRCXGPC7QQOX5D24C3VDYCPP3J" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "batik", rpm: "batik~1.8~9.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

