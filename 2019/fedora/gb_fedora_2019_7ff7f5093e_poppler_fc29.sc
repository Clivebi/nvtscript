if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875603" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2018-20551", "CVE-2018-20481", "CVE-2018-20650", "CVE-2018-18897" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-11 12:15:00 +0000 (Wed, 11 Sep 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:11:44 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for poppler FEDORA-2019-7ff7f5093e" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-7ff7f5093e" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CH33MK2BAV326CV7IKYGMFO4IYX552Z2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'poppler'
  package(s) announced via the FEDORA-2019-7ff7f5093e advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "poppler is a PDF rendering library." );
	script_tag( name: "affected", value: "'poppler' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "poppler", rpm: "poppler~0.67.0~10.fc29", rls: "FC29" ) )){
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

