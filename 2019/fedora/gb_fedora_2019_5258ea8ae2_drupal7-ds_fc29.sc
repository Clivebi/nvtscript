if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876447" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-06-05 02:18:00 +0000 (Wed, 05 Jun 2019)" );
	script_name( "Fedora Update for drupal7-ds FEDORA-2019-5258ea8ae2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-5258ea8ae2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GL2S2TL3NAA43LXBGTTDKNC6KDN67RWS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7-ds'
  package(s) announced via the FEDORA-2019-5258ea8ae2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Display Suite allows you to take full control over how your content is displayed
using a drag and drop interface. Arrange your nodes, views, comments, user data
etc. the way you want without having to work your way through dozens of template
files. A predefined list of layouts (D7 only) is available for even more drag
and drop fun!

By defining custom view modes (build modes in D6), you can define how one piece
of content should be displayed in different places such as teaser lists, search
results, the full node, views etc.

This package provides the following Drupal modules:

  * ds

  * ds_devel (NOTE: Requires install of the devel module)

  * ds_extras

  * ds_format

  * ds_forms

  * ds_search

  * ds_ui" );
	script_tag( name: "affected", value: "'drupal7-ds' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal7-ds", rpm: "drupal7-ds~2.16~1.fc29", rls: "FC29" ) )){
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

