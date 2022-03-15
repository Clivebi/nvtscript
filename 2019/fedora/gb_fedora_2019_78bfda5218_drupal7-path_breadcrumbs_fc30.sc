if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876430" );
	script_version( "2019-12-12T12:03:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-12 12:03:08 +0000 (Thu, 12 Dec 2019)" );
	script_tag( name: "creation_date", value: "2019-06-02 02:13:48 +0000 (Sun, 02 Jun 2019)" );
	script_name( "Fedora Update for drupal7-path_breadcrumbs FEDORA-2019-78bfda5218" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-78bfda5218" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2QODV2FIU6W4ANR625U7HMJ4WRBJI5RV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7-path_breadcrumbs'
  package(s) announced via the FEDORA-2019-78bfda5218 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Path breadcrumbs module helps you to create breadcrumbs for any page with any
selection rules and load any entity from the URL.

Features

  * Breadcrumbs navigation may be added to any kind of page: static
  (example: node/1) or dynamic (example: node/NID).

  * You can load contexts from URL and use it like tokens for breadcrumb path or
  title.

  * You can use selection rules for every breadcrumbs navigation.

  * Supports ALL tokens from Entity tokens module (part of Entity module).

  * You can import/export breadcrumbs (supports single operations, Features and
  Ctools bulk export).

  * Breadcrumbs can be cloned to save you time while building navigation.

  * Module provides rich snippets support for breadcrumbs (RDFa and Microdata).

  * Module provides first/last/odd/even classes to every breadcrumb link.

  * You can change breadcrumbs delimiter.

  * Breadcrumbs could be hidden if they contain only one element.

  * You can disable breadcrumbs and enable them later.

  * All breadcrumb titles are translatable.

  * Usable interface.

This package provides the following Drupal modules:

  * path_breadcrumbs

  * path_breadcrumbs_i18n (requires drupal7-i18n)

  * path_breadcrumbs_ui" );
	script_tag( name: "affected", value: "'drupal7-path_breadcrumbs' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "drupal7-path_breadcrumbs", rpm: "drupal7-path_breadcrumbs~3.4~1.fc30", rls: "FC30" ) )){
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

