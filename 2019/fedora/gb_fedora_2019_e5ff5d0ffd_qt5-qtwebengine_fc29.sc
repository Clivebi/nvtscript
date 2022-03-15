if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876911" );
	script_version( "2021-09-01T11:01:35+0000" );
	script_cve_id( "CVE-2019-5829", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5837", "CVE-2019-5839", "CVE-2019-5842", "CVE-2019-5851", "CVE-2019-5852", "CVE-2019-5854", "CVE-2019-5855", "CVE-2019-5856", "CVE-2019-5857", "CVE-2019-5860", "CVE-2019-5861", "CVE-2019-5862", "CVE-2019-5865" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 11:01:35 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-10-15 02:25:28 +0000 (Tue, 15 Oct 2019)" );
	script_name( "Fedora Update for qt5-qtwebengine FEDORA-2019-e5ff5d0ffd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-e5ff5d0ffd" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EI3DGFVT7CKJO6YVMP55R35HCDVEIC4Z" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the FEDORA-2019-e5ff5d0ffd advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Qt5 - QtWebEngine components." );
	script_tag( name: "affected", value: "'qt5-qtwebengine' package(s) on Fedora 29." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "qt5-qtwebengine", rpm: "qt5-qtwebengine~5.12.5~2.fc29", rls: "FC29" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

