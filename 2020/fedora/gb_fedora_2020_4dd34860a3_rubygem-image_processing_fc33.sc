if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878415" );
	script_version( "2021-07-15T11:00:44+0000" );
	script_cve_id( "CVE-2020-5267", "CVE-2020-8185", "CVE-2020-15169" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-15 11:00:44 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-08 18:58:00 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-10-05 03:09:48 +0000 (Mon, 05 Oct 2020)" );
	script_name( "Fedora: Security Advisory for rubygem-image_processing (FEDORA-2020-4dd34860a3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-4dd34860a3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/V77VWTREGLCV4FYZJECGWKOTTNFELDBQ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-image_processing'
  package(s) announced via the FEDORA-2020-4dd34860a3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "High-level wrapper for processing images for the web with ImageMagick or
libvips." );
	script_tag( name: "affected", value: "'rubygem-image_processing' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "rubygem-image_processing", rpm: "rubygem-image_processing~1.11.0~1.fc33", rls: "FC33" ) )){
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

