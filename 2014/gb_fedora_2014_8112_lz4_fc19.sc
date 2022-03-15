if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867981" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2014-07-21 12:36:41 +0530 (Mon, 21 Jul 2014)" );
	script_tag( name: "cvss_base", value: "4.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:S/C:P/I:P/A:P" );
	script_name( "Fedora Update for lz4 FEDORA-2014-8112" );
	script_tag( name: "affected", value: "lz4 on Fedora 19" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-8112" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135464.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lz4'
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
report = "";
if(release == "FC19"){
	if(!isnull( res = isrpmvuln( pkg: "lz4", rpm: "lz4~r119~1.fc19", rls: "FC19" ) )){
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

