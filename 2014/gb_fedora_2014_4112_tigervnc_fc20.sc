if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867627" );
	script_version( "2020-01-17T13:03:22+0000" );
	script_tag( name: "last_modification", value: "2020-01-17 13:03:22 +0000 (Fri, 17 Jan 2020)" );
	script_tag( name: "creation_date", value: "2014-03-25 10:18:59 +0530 (Tue, 25 Mar 2014)" );
	script_cve_id( "CVE-2014-0011" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for tigervnc FEDORA-2014-4112" );
	script_tag( name: "affected", value: "tigervnc on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-4112" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-March/130495.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tigervnc'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC20" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC20"){
	if(( res = isrpmvuln( pkg: "tigervnc", rpm: "tigervnc~1.3.0~14.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

