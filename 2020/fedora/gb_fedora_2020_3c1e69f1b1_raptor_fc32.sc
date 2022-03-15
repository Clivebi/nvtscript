if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878628" );
	script_version( "2021-07-15T11:00:44+0000" );
	script_cve_id( "CVE-2017-18926" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-15 11:00:44 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-19 03:15:00 +0000 (Thu, 19 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-19 04:21:00 +0000 (Thu, 19 Nov 2020)" );
	script_name( "Fedora: Security Advisory for raptor (FEDORA-2020-3c1e69f1b1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-3c1e69f1b1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WDZRNM45VPTQF2BKRWG4YRCHJGQ2L7NS" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'raptor'
  package(s) announced via the FEDORA-2020-3c1e69f1b1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Raptor is the RDF Parser Toolkit for Redland that provides
a set of standalone RDF parsers, generating triples from RDF/XML
or N-Triples." );
	script_tag( name: "affected", value: "'raptor' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "raptor", rpm: "raptor~1.4.21~33.fc32", rls: "FC32" ) )){
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

