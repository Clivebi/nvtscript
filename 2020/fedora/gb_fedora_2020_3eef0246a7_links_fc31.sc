if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877405" );
	script_version( "2020-02-04T12:23:30+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-02-04 12:23:30 +0000 (Tue, 04 Feb 2020)" );
	script_tag( name: "creation_date", value: "2020-01-31 04:03:47 +0000 (Fri, 31 Jan 2020)" );
	script_name( "Fedora: Security Advisory for links (FEDORA-2020-3eef0246a7)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-3eef0246a7" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TQH7KEIJASJTG2V64Q3AT66W6P4637I4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'links'
  package(s) announced via the FEDORA-2020-3eef0246a7 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Links is a web browser capable of running in either graphics or text mode.
It provides a pull-down menu system, renders complex pages, has partial HTML
4.0 support (including tables, frames and support for multiple character sets
and UTF-8), supports color and monochrome terminals and allows horizontal
scrolling." );
	script_tag( name: "affected", value: "'links' package(s) on Fedora 31." );
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
	if(!isnull( res = isrpmvuln( pkg: "links", rpm: "links~2.20.2~1.fc31", rls: "FC31" ) )){
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

