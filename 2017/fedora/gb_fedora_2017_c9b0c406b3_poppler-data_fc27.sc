if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873723" );
	script_version( "2021-09-13T09:01:48+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 09:01:48 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-23 08:10:30 +0100 (Thu, 23 Nov 2017)" );
	script_cve_id( "CVE-2017-11714", "CVE-2017-9610", "CVE-2017-9611", "CVE-2017-9612", "CVE-2017-9618", "CVE-2017-9619", "CVE-2017-9620", "CVE-2017-9726", "CVE-2017-9727", "CVE-2017-9739", "CVE-2017-9740", "CVE-2017-9835", "CVE-2017-9216", "CVE-2017-8908", "CVE-2017-7948", "CVE-2017-6196" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-17 19:43:00 +0000 (Wed, 17 Apr 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for poppler-data FEDORA-2017-c9b0c406b3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler-data'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "poppler-data on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-c9b0c406b3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/D5KRP2OGBSPD7LH2V5OORJQ64U3AKONZ" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "poppler-data", rpm: "poppler-data~0.4.8~3.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

