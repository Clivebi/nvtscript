if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877444" );
	script_version( "2021-07-19T02:00:45+0000" );
	script_cve_id( "CVE-2019-13626", "CVE-2019-13616", "CVE-2019-12222", "CVE-2019-12218", "CVE-2019-12217", "CVE-2019-12221", "CVE-2019-12219", "CVE-2019-12220", "CVE-2019-12216" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-19 02:00:45 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-22 22:15:00 +0000 (Mon, 22 Jul 2019)" );
	script_tag( name: "creation_date", value: "2020-02-08 04:04:22 +0000 (Sat, 08 Feb 2020)" );
	script_name( "Fedora: Security Advisory for mingw-SDL2 (FEDORA-2020-ff2fe47ba4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-ff2fe47ba4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GY6FDFPYUJ7YPY3XB5U75VJHBSVRVIKO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-SDL2'
  package(s) announced via the FEDORA-2020-ff2fe47ba4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Simple DirectMedia Layer (SDL) is a cross-platform multimedia library
designed to provide fast access to the graphics frame buffer and audio
device." );
	script_tag( name: "affected", value: "'mingw-SDL2' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-SDL2", rpm: "mingw-SDL2~2.0.10~1.fc31", rls: "FC31" ) )){
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

