if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874839" );
	script_version( "2021-06-11T02:00:27+0000" );
	script_tag( name: "last_modification", value: "2021-06-11 02:00:27 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-21 06:05:44 +0200 (Sat, 21 Jul 2018)" );
	script_cve_id( "CVE-2018-7490" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-23 15:24:00 +0000 (Fri, 23 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for uwsgi FEDORA-2018-acfce682f4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'uwsgi'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "affected", value: "uwsgi on Fedora 28" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-acfce682f4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TKEOXIQ3RQDUQLJINDX4VRSEOUKXKLOG" );
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
	if(( res = isrpmvuln( pkg: "uwsgi", rpm: "uwsgi~2.0.17.1~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
