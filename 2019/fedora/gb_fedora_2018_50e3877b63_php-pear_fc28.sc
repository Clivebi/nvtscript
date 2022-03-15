if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875387" );
	script_version( "$Revision: 14225 $" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 15:32:03 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2019-01-01 04:23:50 +0100 (Tue, 01 Jan 2019)" );
	script_name( "Fedora Update for php-pear FEDORA-2018-50e3877b63" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-50e3877b63" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CPZ22U5IJIOSFYEKLWZ7E5GID4XG263A" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'php-pear'
  package(s) announced via the FEDORA-2018-50e3877b63 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "php-pear on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "php-pear", rpm: "php-pear~1.10.7~2.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

