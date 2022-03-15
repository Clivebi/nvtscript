if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878413" );
	script_version( "2021-07-20T02:00:49+0000" );
	script_cve_id( "CVE-2020-5267", "CVE-2020-8185", "CVE-2020-15169" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-20 02:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-08 18:58:00 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-10-05 03:09:44 +0000 (Mon, 05 Oct 2020)" );
	script_name( "Fedora: Security Advisory for rubygem-actionpack (FEDORA-2020-4dd34860a3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-4dd34860a3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XBLUWGVWDBEL4UVXFH5PAX643HSWO7YF" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-actionpack'
  package(s) announced via the FEDORA-2020-4dd34860a3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Eases web-request routing, handling, and response as a half-way front,
half-way page controller. Implemented with specific emphasis on enabling easy
unit/integration testing that doesn&#39, t require a browser." );
	script_tag( name: "affected", value: "'rubygem-actionpack' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "rubygem-actionpack", rpm: "rubygem-actionpack~6.0.3.3~2.fc33", rls: "FC33" ) )){
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

