if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869750" );
	script_version( "2020-03-03T07:50:03+0000" );
	script_tag( name: "last_modification", value: "2020-03-03 07:50:03 +0000 (Tue, 03 Mar 2020)" );
	script_tag( name: "creation_date", value: "2015-07-15 06:19:34 +0200 (Wed, 15 Jul 2015)" );
	script_cve_id( "CVE-2015-4411", "CVE-2015-4410" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for rubygem-moped FEDORA-2015-11138" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-moped'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "rubygem-moped on Fedora 21" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-11138" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-July/161987.html" );
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
	if(( res = isrpmvuln( pkg: "rubygem-moped", rpm: "rubygem-moped~1.5.3~1.fc21", rls: "FC21" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

