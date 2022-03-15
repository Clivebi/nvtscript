if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.867781" );
	script_version( "2020-02-07T08:51:15+0000" );
	script_tag( name: "last_modification", value: "2020-02-07 08:51:15 +0000 (Fri, 07 Feb 2020)" );
	script_tag( name: "creation_date", value: "2014-05-12 09:10:46 +0530 (Mon, 12 May 2014)" );
	script_cve_id( "CVE-2014-2905", "CVE-2014-2914", "CVE-2014-2906" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Fedora Update for fish FEDORA-2014-5794" );
	script_tag( name: "affected", value: "fish on Fedora 20" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "FEDORA", value: "2014-5794" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2014-May/132618.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fish'
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
	if(( res = isrpmvuln( pkg: "fish", rpm: "fish~2.1.0~9.fc20", rls: "FC20" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

