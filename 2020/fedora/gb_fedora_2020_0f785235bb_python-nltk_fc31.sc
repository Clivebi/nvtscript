if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877631" );
	script_version( "2021-07-16T02:00:53+0000" );
	script_cve_id( "CVE-2019-14751" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-07-16 02:00:53 +0000 (Fri, 16 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-27 10:15:00 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-29 03:14:42 +0000 (Sun, 29 Mar 2020)" );
	script_name( "Fedora: Security Advisory for python-nltk (FEDORA-2020-0f785235bb)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-0f785235bb" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QI4IJGLZQ5S7C5LNRNROHAO2P526XE3D" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-nltk'
  package(s) announced via the FEDORA-2020-0f785235bb advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "NLTK is a Python package that simplifies the construction of programs
that process natural language, and defines standard interfaces between
the different components of an NLP system.  It was designed primarily
to help teach graduate and undergraduate students about computational
linguistics, but it is also useful as a framework for implementing
research projects." );
	script_tag( name: "affected", value: "'python-nltk' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "python-nltk", rpm: "python-nltk~3.4.5~2.fc31", rls: "FC31" ) )){
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

