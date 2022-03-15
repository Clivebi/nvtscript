if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868184" );
	script_version( "2020-02-25T10:11:08+0000" );
	script_tag( name: "last_modification", value: "2020-02-25 10:11:08 +0000 (Tue, 25 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-09-14 05:54:30 +0200 (Sun, 14 Sep 2014)" );
	script_cve_id( "CVE-2014-1947" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for GraphicsMagick FEDORA-2014-9624" );
	script_tag( name: "affected", value: "GraphicsMagick on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-9624" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-September/137653.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'GraphicsMagick'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC19" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC19"){
	if(( res = isrpmvuln( pkg: "GraphicsMagick", rpm: "GraphicsMagick~1.3.20~3.fc19", rls: "FC19" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

