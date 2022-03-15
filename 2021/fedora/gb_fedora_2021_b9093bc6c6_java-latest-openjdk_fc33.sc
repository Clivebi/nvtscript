if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879530" );
	script_version( "2021-05-10T06:49:03+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-05-10 06:49:03 +0000 (Mon, 10 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-06 03:13:40 +0000 (Thu, 06 May 2021)" );
	script_name( "Fedora: Security Advisory for java-latest-openjdk (FEDORA-2021-b9093bc6c6)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-b9093bc6c6" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FZ7S2KL3HHHN5Q4G5PNWRHRXKGYUJCSP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-latest-openjdk'
  package(s) announced via the FEDORA-2021-b9093bc6c6 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenJDK 16 runtime environment." );
	script_tag( name: "affected", value: "'java-latest-openjdk' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "java-latest-openjdk", rpm: "java-latest-openjdk~16.0.1.0.9~1.rolling.fc33", rls: "FC33" ) )){
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

