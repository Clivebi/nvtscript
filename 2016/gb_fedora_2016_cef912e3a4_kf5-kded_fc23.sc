if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808898" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-08-02 10:55:51 +0530 (Tue, 02 Aug 2016)" );
	script_cve_id( "CVE-2016-6232" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-11-28 20:31:00 +0000 (Mon, 28 Nov 2016)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for kf5-kded FEDORA-2016-cef912e3a4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kf5-kded'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "kf5-kded on Fedora 23" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-cef912e3a4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NGPVKQ7QJ5FDZZ3WVW7D4PVSPRP2VIVE" );
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
	if(( res = isrpmvuln( pkg: "kf5-kded", rpm: "kf5-kded~5.24.0~1.fc23", rls: "FC23" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

