if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810197" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-12-02 14:03:02 +0100 (Fri, 02 Dec 2016)" );
	script_cve_id( "CVE-2016-6170", "CVE-2016-8864" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 17:44:00 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for bind99 FEDORA-2016-8e39076950" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bind99'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "bind99 on Fedora 23" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-8e39076950" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/6SIT42RZAQZYTO7X57QSGAAEG4LNQAQC" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC23" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC23"){
	if(( res = isrpmvuln( pkg: "bind99", rpm: "bind99~9.9.9~4.P4.fc23", rls: "FC23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

