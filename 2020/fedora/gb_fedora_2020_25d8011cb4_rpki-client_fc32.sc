if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878178" );
	script_version( "2020-08-14T06:59:33+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-14 06:59:33 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-09 03:20:19 +0000 (Sun, 09 Aug 2020)" );
	script_name( "Fedora: Security Advisory for rpki-client (FEDORA-2020-25d8011cb4)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-25d8011cb4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UE2U5TAINPR2UZ2INJXY2BP7QD7CDWVG" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rpki-client'
  package(s) announced via the FEDORA-2020-25d8011cb4 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenBSD rpki-client is a free, easy-to-use implementation of the
Resource Public Key Infrastructure (RPKI) for Relying Parties (RP) to
facilitate validation of the Route Origin of a BGP announcement. The
program queries the RPKI repository system, downloads and validates
Route Origin Authorisations (ROAs) and finally outputs Validated ROA
Payloads (VRPs) in the configuration format of OpenBGPD, BIRD, and
also as CSV or JSON objects for consumption by other routing stacks." );
	script_tag( name: "affected", value: "'rpki-client' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "rpki-client", rpm: "rpki-client~6.7p1~1.fc32", rls: "FC32" ) )){
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

