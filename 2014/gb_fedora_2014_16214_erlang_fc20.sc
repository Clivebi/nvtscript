if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.868605" );
	script_version( "2020-03-13T10:06:41+0000" );
	script_tag( name: "last_modification", value: "2020-03-13 10:06:41 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2014-12-15 05:56:51 +0100 (Mon, 15 Dec 2014)" );
	script_cve_id( "CVE-2014-1693" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for erlang FEDORA-2014-16214" );
	script_tag( name: "summary", value: "Check the version of erlang" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "erlang on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2014-16214" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-December/146184.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
report = "";
if(release == "FC20"){
	if(!isnull( res = isrpmvuln( pkg: "erlang", rpm: "erlang~R16B~03.10.fc20", rls: "FC20" ) )){
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

