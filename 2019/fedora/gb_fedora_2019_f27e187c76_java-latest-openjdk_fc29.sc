if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876602" );
	script_version( "2019-07-25T11:54:35+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-07-25 02:18:53 +0000 (Thu, 25 Jul 2019)" );
	script_name( "Fedora Update for java-latest-openjdk FEDORA-2019-f27e187c76" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-f27e187c76" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z7EHKU6L242SNTHU6XCEZ237ZXFRPQHP" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'java-latest-openjdk'
  package(s) announced via the FEDORA-2019-f27e187c76 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The OpenJDK runtime environment." );
	script_tag( name: "affected", value: "'java-latest-openjdk' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "java-latest-openjdk", rpm: "java-latest-openjdk~12.0.2.9~1.rolling.fc29", rls: "FC29" ) )){
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

