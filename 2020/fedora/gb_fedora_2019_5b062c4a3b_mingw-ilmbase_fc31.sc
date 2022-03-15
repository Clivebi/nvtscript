if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877278" );
	script_version( "2021-07-20T02:00:49+0000" );
	script_cve_id( "CVE-2018-18443", "CVE-2018-18444" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-20 02:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-09-23 20:15:00 +0000 (Mon, 23 Sep 2019)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:35:21 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for mingw-ilmbase FEDORA-2019-5b062c4a3b" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-5b062c4a3b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IZN7WUH3SR6DSRODRB4SLFTBKP74FVC5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-ilmbase'
  package(s) announced via the FEDORA-2019-5b062c4a3b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows ilmbase library." );
	script_tag( name: "affected", value: "'mingw-ilmbase' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "mingw-ilmbase", rpm: "mingw-ilmbase~2.3.0~3.fc31", rls: "FC31" ) )){
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

