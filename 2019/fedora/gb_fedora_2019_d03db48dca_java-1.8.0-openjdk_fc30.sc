if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876934" );
	script_version( "2020-03-13T07:50:12+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-13 07:50:12 +0000 (Fri, 13 Mar 2020)" );
	script_tag( name: "creation_date", value: "2019-10-26 02:27:27 +0000 (Sat, 26 Oct 2019)" );
	script_name( "Fedora Update for java-1.8.0-openjdk FEDORA-2019-d03db48dca" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-d03db48dca" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LMNNDWNV7VY2DJVK2YP55QPM67M3I3ZL" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.8.0-openjdk'
  package(s) announced via the FEDORA-2019-d03db48dca advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenJDK runtime environment 8." );
	script_tag( name: "affected", value: "'java-1.8.0-openjdk' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk", rpm: "java-1.8.0-openjdk~1.8.0.232.b09~0.fc30", rls: "FC30" ) )){
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

