if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867698" );
	script_version( "2020-02-25T10:11:08+0000" );
	script_tag( name: "last_modification", value: "2020-02-25 10:11:08 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-04-16 11:22:36 +0530 (Wed, 16 Apr 2014)" );
	script_cve_id( "CVE-2014-1958", "CVE-2014-1947", "CVE-2014-2030" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for ImageMagick FEDORA-2014-4969" );
	script_tag( name: "affected", value: "ImageMagick on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-4969" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-April/131475.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "ImageMagick", rpm: "ImageMagick~6.8.6.3~4.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

