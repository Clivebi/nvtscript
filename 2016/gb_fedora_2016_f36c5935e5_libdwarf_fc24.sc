if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808418" );
	script_version( "2019-10-07T07:48:28+0000" );
	script_tag( name: "last_modification", value: "2019-10-07 07:48:28 +0000 (Mon, 07 Oct 2019)" );
	script_tag( name: "creation_date", value: "2016-06-08 15:29:14 +0200 (Wed, 08 Jun 2016)" );
	script_cve_id( "CVE-2016-2091", "CVE-2016-2050" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for libdwarf FEDORA-2016-f36c5935e5" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libdwarf'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "libdwarf on Fedora 24" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-f36c5935e5" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CSMWGIIQTEPYCQ756IBTC7ZZUJ64NZV4" );
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
	if(( res = isrpmvuln( pkg: "libdwarf", rpm: "libdwarf~20160507~1.fc24", rls: "FC24" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

