if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877821" );
	script_version( "2020-05-15T04:25:55+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-05-15 04:25:55 +0000 (Fri, 15 May 2020)" );
	script_tag( name: "creation_date", value: "2020-05-11 03:22:51 +0000 (Mon, 11 May 2020)" );
	script_name( "Fedora: Security Advisory for java-11-openjdk (FEDORA-2020-372eeb28f3)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2020-372eeb28f3" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KHT3SVDQYYYJKKHXI6K6LOTOIRYRNYDJ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the FEDORA-2020-372eeb28f3 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenJDK runtime environment." );
	script_tag( name: "affected", value: "'java-11-openjdk' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "java-11-openjdk", rpm: "java-11-openjdk~11.0.7.10~0.fc31", rls: "FC31" ) )){
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

