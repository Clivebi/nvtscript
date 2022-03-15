if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879772" );
	script_version( "2021-09-06T09:01:34+0000" );
	script_cve_id( "CVE-2021-3589", "CVE-2021-3598", "CVE-2021-3605" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-01 02:04:00 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-06-20 03:17:02 +0000 (Sun, 20 Jun 2021)" );
	script_name( "Fedora: Security Advisory for mingw-openexr (FEDORA-2021-25fe4291c9)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-25fe4291c9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/O2GOMRCHU5R7NOJAD3ARM7OCTLDNIMSK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-openexr'
  package(s) announced via the FEDORA-2021-25fe4291c9 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows openexr library." );
	script_tag( name: "affected", value: "'mingw-openexr' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "mingw-openexr", rpm: "mingw-openexr~2.5.5~3.fc34", rls: "FC34" ) )){
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

