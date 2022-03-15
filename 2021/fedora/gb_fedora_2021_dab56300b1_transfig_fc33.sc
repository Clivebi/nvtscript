if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879715" );
	script_version( "2021-08-20T09:01:03+0000" );
	script_cve_id( "CVE-2021-3561" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 09:01:03 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-07 03:15:00 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-07 03:09:22 +0000 (Mon, 07 Jun 2021)" );
	script_name( "Fedora: Security Advisory for transfig (FEDORA-2021-dab56300b1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-dab56300b1" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JKMOIQX6GULVSYXLYW5JQY6KJNTWV3E4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'transfig'
  package(s) announced via the FEDORA-2021-dab56300b1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The transfig utility creates a makefile which translates FIG (created
by xfig) or PIC figures into a specified LaTeX graphics language (for
example, PostScript(TM)).  Transfig is used to create TeX documents
which are portable (i.e., they can be printed in a wide variety of
environments).

Install transfig if you need a utility for translating FIG or PIC
figures into certain graphics languages." );
	script_tag( name: "affected", value: "'transfig' package(s) on Fedora 33." );
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
	if(!isnull( res = isrpmvuln( pkg: "transfig", rpm: "transfig~3.2.8a~2.fc33", rls: "FC33" ) )){
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

