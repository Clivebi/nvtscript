if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873184" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-04 12:46:08 +0530 (Fri, 04 Aug 2017)" );
	script_cve_id( "CVE-2017-7515", "CVE-2017-9775", "CVE-2017-9776", "CVE-2017-9865" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-12 17:27:00 +0000 (Tue, 12 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for mingw-poppler FEDORA-2017-bbb664e0a0" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-poppler'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "mingw-poppler on Fedora 26" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-bbb664e0a0" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ES7SGGN4XFUZUI327DPKVVYPTOQQRBKF" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "mingw32-poppler", rpm: "mingw32-poppler~0.52.0~3.fc26", rls: "FC26" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

