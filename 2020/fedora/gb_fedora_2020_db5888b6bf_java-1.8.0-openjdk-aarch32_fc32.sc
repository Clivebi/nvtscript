if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877581" );
	script_version( "2020-03-20T06:19:59+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-20 06:19:59 +0000 (Fri, 20 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-17 04:08:26 +0000 (Tue, 17 Mar 2020)" );
	script_name( "Fedora: Security Advisory for java-1.8.0-openjdk-aarch32 (FEDORA-2020-db5888b6bf)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC32" );
	script_xref( name: "FEDORA", value: "2020-db5888b6bf" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WBGGKHSEV5PL3YVSB6YQMDDZAURHPMNY" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-1.8.0-openjdk-aarch32'
  package(s) announced via the FEDORA-2020-db5888b6bf advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "A preview release of the upstream OpenJDK AArch32 porting project.
The OpenJDK runtime environment." );
	script_tag( name: "affected", value: "'java-1.8.0-openjdk-aarch32' package(s) on Fedora 32." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-1.8.0-openjdk-aarch32", rpm: "java-1.8.0-openjdk-aarch32~1.8.0.242.b07~1.fc32", rls: "FC32" ) )){
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

