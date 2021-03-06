if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876456" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-06-05 02:18:11 +0000 (Wed, 05 Jun 2019)" );
	script_name( "Fedora Update for drupal7-module_filter FEDORA-2019-0e10310204" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-0e10310204" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YLKQ4C724QG4U4XFVR23A7MRG4NRWRL7" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7-module_filter'
  package(s) announced via the FEDORA-2019-0e10310204 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The modules list page can become quite big when dealing with a fairly large site
or even just a dev site meant for testing new
and various modules being considered.
What this module aims to accomplish is the ability to quickly find the module
you are looking for without having to rely on the browsers search feature
which more times than not shows you the module name in the &#39, Required by&#39,
or &#39, Depends on&#39, sections of the various modules
or even some other location on the page like a menu item.

This package provides the following Drupal module(s):

  * module_filter" );
	script_tag( name: "affected", value: "'drupal7-module_filter' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal7-module_filter", rpm: "drupal7-module_filter~2.2~1.fc29", rls: "FC29" ) )){
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

