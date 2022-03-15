if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869017" );
	script_version( "2020-02-10T07:58:04+0000" );
	script_tag( name: "last_modification", value: "2020-02-10 07:58:04 +0000 (Mon, 10 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-02-16 05:44:23 +0100 (Mon, 16 Feb 2015)" );
	script_cve_id( "CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141", "CVE-2014-9636" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for unzip FEDORA-2015-2035" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'unzip'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "unzip on Fedora 21" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-2035" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-February/150038.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC21" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC21"){
	if(( res = isrpmvuln( pkg: "unzip", rpm: "unzip~6.0~20.fc21", rls: "FC21" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

