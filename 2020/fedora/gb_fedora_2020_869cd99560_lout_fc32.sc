if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878548" );
	script_version( "2021-07-21T02:01:11+0000" );
	script_cve_id( "CVE-2019-19918", "CVE-2019-19917" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-21 02:01:11 +0000 (Wed, 21 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-10-31 04:14:27 +0000 (Sat, 31 Oct 2020)" );
	script_name( "Fedora: Security Advisory for lout (FEDORA-2020-869cd99560)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-869cd99560" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NEJVEIQMRXJ26ZT6657W5RYH7YECVGNB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lout'
  package(s) announced via the FEDORA-2020-869cd99560 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Lout is a document formatting system designed and implemented by Jeffrey
Kingston at the Basser Department of Computer Science, University of
Sydney, Australia. The system reads a high-level description of a document
similar in style to LaTeX and produces a PostScript file which can be
printed on most laser printers and graphic display devices. Plain text
output is also available, PDF output is limited but working (e.g. no
graphics). Lout is inherently multilingual. Adding new languages is easy." );
	script_tag( name: "affected", value: "'lout' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "lout", rpm: "lout~3.40~18.fc32", rls: "FC32" ) )){
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
