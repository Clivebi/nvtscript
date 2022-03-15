if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872248" );
	script_version( "$Revision: 14225 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 15:32:03 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2017-01-10 05:52:50 +0100 (Tue, 10 Jan 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for tinymce FEDORA-2016-8d8d7d6d47" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tinymce'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "tinymce on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-8d8d7d6d47" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2ESVENMKIFUKMJL7WSH73FK6TFGFGUAT" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC25" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC25"){
	if(( res = isrpmvuln( pkg: "tinymce", rpm: "tinymce~4.5.1~1.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

