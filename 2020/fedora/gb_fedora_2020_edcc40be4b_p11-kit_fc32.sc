if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878755" );
	script_version( "2020-12-30T05:23:09+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-30 05:23:09 +0000 (Wed, 30 Dec 2020)" );
	script_tag( name: "creation_date", value: "2020-12-22 04:13:13 +0000 (Tue, 22 Dec 2020)" );
	script_name( "Fedora: Security Advisory for p11-kit (FEDORA-2020-edcc40be4b)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-edcc40be4b" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KMJ7K6MTPKMWD3EUQ4WMTQ2QXQCBRH7G" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'p11-kit'
  package(s) announced via the FEDORA-2020-edcc40be4b advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "p11-kit provides a way to load and enumerate PKCS#11 modules, as well
as a standard configuration setup for installing PKCS#11 modules in
such a way that they&#39, re discoverable." );
	script_tag( name: "affected", value: "'p11-kit' package(s) on Fedora 32." );
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
if(release == "FC32"){
	if(!isnull( res = isrpmvuln( pkg: "p11-kit", rpm: "p11-kit~0.23.22~1.fc32", rls: "FC32" ) )){
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

