if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.874278" );
	script_version( "2021-06-08T02:00:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-08 02:00:22 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-26 08:32:45 +0200 (Mon, 26 Mar 2018)" );
	script_cve_id( "CVE-2017-15429", "CVE-2018-6033", "CVE-2018-6060", "CVE-2018-6062", "CVE-2018-6064", "CVE-2018-6069", "CVE-2018-6071", "CVE-2018-6073", "CVE-2018-6076", "CVE-2018-6079", "CVE-2018-6081", "CVE-2018-6082" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-20 18:11:00 +0000 (Tue, 20 Nov 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for qt5-qtwebengine FEDORA-2018-024afa2d48" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "qt5-qtwebengine on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2018-024afa2d48" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/36XZOQSLKLPBFKLG6D6YPO3YQIIWPTSU" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC26" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC26"){
	if(( res = isrpmvuln( pkg: "qt5-qtwebengine", rpm: "qt5-qtwebengine~5.10.1~4.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

