if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876066" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:33:34 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for drupal7-link FEDORA-2019-55788aeb71" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-55788aeb71" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YDXL5UTEOTCRIIIHAQL4CKNWT4USV7TN" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7-link'
  package(s) announced via the FEDORA-2019-55788aeb71 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The link module can be count to the top 50 modules in Drupal installations and
provides a standard custom content field for links. With this module links can
be added easily to any content types and profiles and include advanced
validating and different ways of storing internal or external links and URLs.
It also supports additional link text title, site wide tokens for titles and
title attributes, target attributes, CSS class attribution, static repeating
values, input conversion, and many more.

This package provides the following Drupal module:

  * link" );
	script_tag( name: "affected", value: "'drupal7-link' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal7-link", rpm: "drupal7-link~1.6~1.fc29", rls: "FC29" ) )){
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

