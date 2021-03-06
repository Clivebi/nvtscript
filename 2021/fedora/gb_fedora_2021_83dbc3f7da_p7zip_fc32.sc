if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879508" );
	script_version( "2021-05-10T06:49:03+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-10 06:49:03 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-02 03:12:08 +0000 (Sun, 02 May 2021)" );
	script_name( "Fedora: Security Advisory for p7zip (FEDORA-2021-83dbc3f7da)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-83dbc3f7da" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NOL7OGIR6MHOPX2R2Q7Z52SW63NUYO7Z" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'p7zip'
  package(s) announced via the FEDORA-2021-83dbc3f7da advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "p7zip is a port of 7za.exe for Unix." );
	script_tag( name: "affected", value: "'p7zip' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "p7zip", rpm: "p7zip~16.02~20.fc32", rls: "FC32" ) )){
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

