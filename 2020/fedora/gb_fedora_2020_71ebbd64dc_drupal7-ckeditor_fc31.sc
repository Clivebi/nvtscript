if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877697" );
	script_version( "2020-04-21T09:23:28+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-21 09:23:28 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2020-04-14 03:09:12 +0000 (Tue, 14 Apr 2020)" );
	script_name( "Fedora: Security Advisory for drupal7-ckeditor (FEDORA-2020-71ebbd64dc)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-71ebbd64dc" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VBXTWPTIODNIIRJ4AFOKVUKQYYGHWO6X" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'drupal7-ckeditor'
  package(s) announced via the FEDORA-2020-71ebbd64dc advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This module will allow Drupal to replace textarea fields with the CKEditor - a
visual HTML editor [1], usually called a WYSIWYG editor. This HTML text editor
brings many of the powerful WYSIWYG editing functions of known desktop editors
like Word to the web. It&#39, s very fast and doesn&#39, t require any kind of
installation on the client computer." );
	script_tag( name: "affected", value: "'drupal7-ckeditor' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "drupal7-ckeditor", rpm: "drupal7-ckeditor~1.19~1.fc31", rls: "FC31" ) )){
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

