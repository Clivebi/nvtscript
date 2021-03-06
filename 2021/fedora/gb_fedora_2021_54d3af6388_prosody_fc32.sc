if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.878963" );
	script_version( "2021-03-01T04:08:26+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-03-01 04:08:26 +0000 (Mon, 01 Mar 2021)" );
	script_tag( name: "creation_date", value: "2021-02-25 04:03:03 +0000 (Thu, 25 Feb 2021)" );
	script_name( "Fedora: Security Advisory for prosody (FEDORA-2021-54d3af6388)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-54d3af6388" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/RZ2LT7DJPQEM7PQS7KIJH423BOPL3UIC" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'prosody'
  package(s) announced via the FEDORA-2021-54d3af6388 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Prosody is a flexible communications server for Jabber/XMPP written in Lua.
It aims to be easy to use, and light on resources. For developers it aims
to be easy to extend and give a flexible system on which to rapidly develop
added functionality, or prototype new protocols." );
	script_tag( name: "affected", value: "'prosody' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "prosody", rpm: "prosody~0.11.8~1.fc32", rls: "FC32" ) )){
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

