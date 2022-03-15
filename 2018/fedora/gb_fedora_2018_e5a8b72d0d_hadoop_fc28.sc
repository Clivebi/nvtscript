if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874800" );
	script_version( "2021-06-07T11:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 11:00:20 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-15 06:01:10 +0200 (Sun, 15 Jul 2018)" );
	script_cve_id( "CVE-2018-8009", "CVE-2016-6811", "CVE-2017-15718", "CVE-2017-15713", "CVE-2017-3166" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-10 13:12:00 +0000 (Thu, 10 May 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for hadoop FEDORA-2018-e5a8b72d0d" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'hadoop'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "hadoop on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-e5a8b72d0d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TAN65UU2GAYHTIGHR5BDCMBJAFLLFGLM" );
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
	if(( res = isrpmvuln( pkg: "hadoop", rpm: "hadoop~2.7.6~4.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

