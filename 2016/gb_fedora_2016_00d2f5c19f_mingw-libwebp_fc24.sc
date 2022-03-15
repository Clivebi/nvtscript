if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810194" );
	script_version( "2020-07-21T08:11:15+0000" );
	script_tag( name: "last_modification", value: "2020-07-21 08:11:15 +0000 (Tue, 21 Jul 2020)" );
	script_tag( name: "creation_date", value: "2016-12-02 14:07:01 +0100 (Fri, 02 Dec 2016)" );
	script_cve_id( "CVE-2016-9085" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for mingw-libwebp FEDORA-2016-00d2f5c19f" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-libwebp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "mingw-libwebp on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-00d2f5c19f" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LG5Q42J7EJDKQKWTTHCO4YZMOMP74YPQ" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC24" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC24"){
	if(( res = isrpmvuln( pkg: "mingw-libwebp", rpm: "mingw-libwebp~0.5.1~2.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
