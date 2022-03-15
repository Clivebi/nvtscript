if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872630" );
	script_version( "2021-09-10T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 08:01:37 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-03 14:19:11 +0530 (Wed, 03 May 2017)" );
	script_cve_id( "CVE-2016-10210", "CVE-2016-10211", "CVE-2017-5923", "CVE-2017-5924", "CVE-2017-8294" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-02 01:59:00 +0000 (Tue, 02 May 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for yara FEDORA-2017-11ac1e31eb" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'yara'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "yara on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-11ac1e31eb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3U5GWT3EM75FEZ2DWRMSLL33PZUATIC6" );
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
	if(( res = isrpmvuln( pkg: "yara", rpm: "yara~3.5.0~7.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
