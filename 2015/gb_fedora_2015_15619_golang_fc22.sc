if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.869978" );
	script_version( "2020-02-18T15:18:54+0000" );
	script_tag( name: "last_modification", value: "2020-02-18 15:18:54 +0000 (Tue, 18 Feb 2020)" );
	script_tag( name: "creation_date", value: "2015-10-02 07:09:32 +0200 (Fri, 02 Oct 2015)" );
	script_cve_id( "CVE-2015-5739", "CVE-2015-5740", "CVE-2015-5741" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for golang FEDORA-2015-15619" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'golang'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "golang on Fedora 22" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2015-15619" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2015-October/167997.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC22" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC22"){
	if(( res = isrpmvuln( pkg: "golang", rpm: "golang~1.5.1~0.fc22", rls: "FC22" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

