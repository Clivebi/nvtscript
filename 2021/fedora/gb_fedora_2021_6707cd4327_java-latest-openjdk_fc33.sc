if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879905" );
	script_version( "2021-08-03T06:52:21+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-03 06:52:21 +0000 (Tue, 03 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-08-02 03:18:30 +0000 (Mon, 02 Aug 2021)" );
	script_name( "Fedora: Security Advisory for java-latest-openjdk (FEDORA-2021-6707cd4327)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-6707cd4327" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XA26HK5M2PPUZX4R22C52FVLETEM3YT2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-latest-openjdk'
  package(s) announced via the FEDORA-2021-6707cd4327 advisory." );
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
	if(!isnull( res = isrpmvuln( pkg: "java-latest-openjdk", rpm: "java-latest-openjdk~16.0.2.0.7~1.rolling.fc33", rls: "FC33" ) )){
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

