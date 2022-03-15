if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878376" );
	script_version( "2021-07-15T11:00:44+0000" );
	script_cve_id( "CVE-2020-5238" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-15 11:00:44 +0000 (Thu, 15 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-06 18:15:00 +0000 (Tue, 06 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-09-29 03:19:56 +0000 (Tue, 29 Sep 2020)" );
	script_name( "Fedora: Security Advisory for pandoc-citeproc (FEDORA-2020-c39d7a562c)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "FEDORA", value: "2020-c39d7a562c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TCDHBTUFIOYRIS5HAS6PZNBNMB7IOAX3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'pandoc-citeproc'
  package(s) announced via the FEDORA-2020-c39d7a562c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The pandoc-citeproc library supports automatic generation of citations and a
bibliography in pandoc documents using the Citation Style Language (CSL) macro
language.

In addition to a library, the package includes an executable, pandoc-citeproc,
which works as a pandoc filter and also has a mode for converting bibliographic
databases into CSL JSON and pandoc YAML metadata formats.

pandoc-citeproc originated as a fork of Andrea Rossato&#39, s citeproc-hs." );
	script_tag( name: "affected", value: "'pandoc-citeproc' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "pandoc-citeproc", rpm: "pandoc-citeproc~0.17.0.1~3.fc33", rls: "FC33" ) )){
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

