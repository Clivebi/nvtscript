if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818430" );
	script_version( "2021-09-22T05:42:45+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-22 05:42:45 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-22 01:19:12 +0000 (Wed, 22 Sep 2021)" );
	script_name( "Fedora: Security Advisory for dovecot-fts-xapian (FEDORA-2021-e5f64ca6ce)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-e5f64ca6ce" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UUJAXPNGSSVOBO5XAGNKIBLKZUC6MV3L" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dovecot-fts-xapian'
  package(s) announced via the FEDORA-2021-e5f64ca6ce advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This project intends to provide a straightforward, simple and
maintenance free, way to configure FTS plugin for Dovecot

This effort came after Dovecot team decided to deprecate
'fts_squat' included in the dovecot core, and due to the
complexity of the Solr plugin capabilitles, un-needed for most
users." );
	script_tag( name: "affected", value: "'dovecot-fts-xapian' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "dovecot-fts-xapian", rpm: "dovecot-fts-xapian~1.4.13~1.fc34", rls: "FC34" ) )){
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

