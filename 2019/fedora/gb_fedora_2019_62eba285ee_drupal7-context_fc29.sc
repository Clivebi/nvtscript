if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876453" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-06-05 02:18:06 +0000 (Wed, 05 Jun 2019)" );
	script_name( "Fedora Update for drupal7-context FEDORA-2019-62eba285ee" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-62eba285ee" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HIEIOEBSFJSVXPJ3HFUYD4B5WVO2EJ2S" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7-context'
  package(s) announced via the FEDORA-2019-62eba285ee advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Context allows you to manage contextual conditions and reactions for different
portions of your site. You can think of each context as representing a
'section'
of your site. For each context, you can choose the conditions that trigger this
context to be active and choose different aspects of Drupal that should react to
this active context.

Think of conditions as a set of rules that are checked during page load to see
what context is active. Any reactions that are associated with active contexts
are then fired.

This package provides the following Drupal modules:

  * context

  * context_layouts

  * context_ui" );
	script_tag( name: "affected", value: "'drupal7-context' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal7-context", rpm: "drupal7-context~3.10~1.fc29", rls: "FC29" ) )){
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

