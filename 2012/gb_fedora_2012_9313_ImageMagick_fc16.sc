if(description){
	script_xref( name: "URL", value: "http://lists.fedoraproject.org/pipermail/package-announce/2012-June/082623.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.864490" );
	script_version( "2021-08-27T11:01:07+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 11:01:07 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-06-25 09:51:49 +0530 (Mon, 25 Jun 2012)" );
	script_cve_id( "CVE-2012-0259", "CVE-2012-1620" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 18:42:00 +0000 (Fri, 31 Jul 2020)" );
	script_xref( name: "FEDORA", value: "2012-9313" );
	script_name( "Fedora Update for ImageMagick FEDORA-2012-9313" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC16" );
	script_tag( name: "affected", value: "ImageMagick on Fedora 16" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC16"){
	if(( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~6.7.0.10~5.fc16", rls: "FC16" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

